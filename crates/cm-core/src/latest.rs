//! A bounded, single-producer/single-consumer latest-value channel.
//!
//! Publishing replaces the one pending value. The channel does not retain
//! history or wait for the receiver. Values removed from the slot are dropped
//! after releasing the channel mutex, so user-defined destructors never run
//! while channel state is locked.

use std::fmt;
use std::sync::{Arc, Mutex};

/// The sending side's receiver has been dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurfaceClosed;

struct State<T> {
    slot: Option<T>,
    sender_alive: bool,
    receiver_alive: bool,
}

/// The unique producer for a [`LatestReceiver`].
pub struct LatestSender<T> {
    state: Arc<Mutex<State<T>>>,
}

/// The unique consumer for a [`LatestSender`].
pub struct LatestReceiver<T> {
    state: Arc<Mutex<State<T>>>,
}

impl<T> fmt::Debug for LatestSender<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LatestSender { .. }")
    }
}

impl<T> fmt::Debug for LatestReceiver<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LatestReceiver { .. }")
    }
}

/// Create an empty channel with one producer and one consumer.
pub fn latest_channel<T>() -> (LatestSender<T>, LatestReceiver<T>) {
    let state = Arc::new(Mutex::new(State {
        slot: None,
        sender_alive: true,
        receiver_alive: true,
    }));
    (
        LatestSender {
            state: Arc::clone(&state),
        },
        LatestReceiver { state },
    )
}

impl<T> LatestSender<T> {
    /// Publish a value, replacing any pending value.
    ///
    /// Returns `Ok(false)` if the slot was empty, `Ok(true)` if a value was
    /// replaced, or returns the input value intact if the receiver is closed.
    pub fn publish(&self, value: T) -> Result<bool, T> {
        let mut rejected = None;
        let mut replaced = None;
        let result = {
            let mut state = self.state.lock().expect("latest channel mutex poisoned");
            if !state.receiver_alive {
                rejected = Some(value);
                Err(())
            } else {
                replaced = state.slot.replace(value);
                Ok(replaced.is_some())
            }
        };
        drop(replaced);
        match result {
            Ok(was_replaced) => Ok(was_replaced),
            Err(()) => Err(rejected.expect("rejected value is present")),
        }
    }
}

impl<T> LatestReceiver<T> {
    /// Take the latest pending value, or report empty/closed state.
    ///
    /// A pending final value is returned once after the sender is dropped;
    /// closure is reported only after that value has been consumed.
    pub fn try_recv_latest(&self) -> Result<Option<T>, SurfaceClosed> {
        {
            let mut state = self.state.lock().expect("latest channel mutex poisoned");
            if !state.receiver_alive {
                Err(SurfaceClosed)
            } else if let Some(value) = state.slot.take() {
                Ok(Some(value))
            } else if state.sender_alive {
                Ok(None)
            } else {
                Err(SurfaceClosed)
            }
        }
    }
}

impl<T> Drop for LatestSender<T> {
    fn drop(&mut self) {
        let mut state = self.state.lock().expect("latest channel mutex poisoned");
        state.sender_alive = false;
    }
}

impl<T> Drop for LatestReceiver<T> {
    fn drop(&mut self) {
        let discarded = {
            let mut state = self.state.lock().expect("latest channel mutex poisoned");
            state.receiver_alive = false;
            state.slot.take()
        };
        drop(discarded);
    }
}

#[cfg(test)]
mod tests {
    use super::{SurfaceClosed, latest_channel};
    use std::sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use std::thread;

    #[test]
    fn empty_replacement_and_latest_value_have_no_history() {
        let (sender, receiver) = latest_channel();
        assert_eq!(receiver.try_recv_latest(), Ok(None));
        assert_eq!(sender.publish(1), Ok(false));
        assert_eq!(sender.publish(2), Ok(true));
        assert_eq!(sender.publish(3), Ok(true));
        assert_eq!(receiver.try_recv_latest(), Ok(Some(3)));
        assert_eq!(receiver.try_recv_latest(), Ok(None));
    }

    #[test]
    fn replacement_and_receiver_drop_release_pending_values() {
        struct CountDrop(Arc<AtomicUsize>);
        impl Drop for CountDrop {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let drops = Arc::new(AtomicUsize::new(0));
        let (sender, receiver) = latest_channel();
        assert!(matches!(
            sender.publish(CountDrop(Arc::clone(&drops))),
            Ok(false)
        ));
        assert!(matches!(
            sender.publish(CountDrop(Arc::clone(&drops))),
            Ok(true)
        ));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(receiver);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        let returned = match sender.publish(CountDrop(Arc::clone(&drops))) {
            Err(value) => value,
            Ok(_) => panic!("receiver was already dropped"),
        };
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        drop(returned);
        assert_eq!(drops.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn sender_drop_delivers_final_value_then_reports_closed() {
        let (sender, receiver) = latest_channel();
        sender.publish("final").unwrap();
        drop(sender);
        assert_eq!(receiver.try_recv_latest(), Ok(Some("final")));
        assert_eq!(receiver.try_recv_latest(), Err(SurfaceClosed));
    }

    #[test]
    fn receiver_drop_closes_admission_immediately() {
        let (sender, receiver) = latest_channel::<String>();
        drop(receiver);
        let rejected = sender.publish(String::from("preserved")).unwrap_err();
        assert_eq!(rejected, "preserved");
    }

    #[test]
    fn debug_output_redacts_pending_payload() {
        let (sender, receiver) = latest_channel();
        sender.publish("sensitive payload").unwrap();
        assert!(!format!("{sender:?}").contains("sensitive payload"));
        assert!(!format!("{receiver:?}").contains("sensitive payload"));
    }

    #[test]
    fn slow_reentrant_destructor_runs_outside_channel_lock() {
        enum Item {
            Reenter(Arc<Mutex<Option<super::LatestReceiver<Item>>>>),
            Value(usize),
        }
        impl Drop for Item {
            fn drop(&mut self) {
                if let Self::Reenter(receiver_slot) = self
                    && let Some(receiver) = receiver_slot.lock().unwrap().take()
                {
                    match receiver.try_recv_latest() {
                        Ok(Some(Self::Value(7))) => {}
                        _ => panic!("reentrant receive did not observe replacement"),
                    }
                }
            }
        }
        let (sender, receiver) = latest_channel::<Item>();
        let reentrant_receiver = Arc::new(Mutex::new(Some(receiver)));
        assert!(matches!(
            sender.publish(Item::Reenter(Arc::clone(&reentrant_receiver))),
            Ok(false)
        ));
        assert!(matches!(sender.publish(Item::Value(7)), Ok(true)));
        assert!(reentrant_receiver.lock().unwrap().is_none());
    }

    #[test]
    fn concurrent_producer_and_slow_consumer_keep_only_latest() {
        const COUNT: usize = 50_000;
        let (sender, receiver) = latest_channel();
        let ready = Arc::new(Barrier::new(2));
        let producer_ready = Arc::clone(&ready);
        let producer = thread::spawn(move || {
            producer_ready.wait();
            for value in 0..COUNT {
                sender.publish(value).unwrap();
                if value % 1000 == 0 {
                    thread::yield_now();
                }
            }
        });
        ready.wait();
        let mut last = None;
        loop {
            match receiver.try_recv_latest() {
                Ok(Some(value)) => last = Some(value),
                Ok(None) => thread::yield_now(),
                Err(SurfaceClosed) => break,
            }
        }
        producer.join().unwrap();
        assert_eq!(last, Some(COUNT - 1));
    }
}
