use std::io::Cursor;
use std::time::{Duration, Instant};

use super::frame::FramePixels;
use super::png::{encode_tiles, encode_tiles_with_limits};
use super::state::{
    AckResult, FrameAck, FrameState, NativeFrame, OfferResult, StreamOutput,
    codec_reservation_bytes,
};
use super::{
    FRAME_ACK_TIMEOUT, FRAME_INTERVAL, FrameKind, MAX_FRAME_PNG_BYTES, MAX_TILE_COUNT,
    MAX_TILE_PLAN_BYTES, MAX_TILE_PNG_BYTES, MAX_WIDTH, StreamError,
};

fn pixels(width: u16, height: u16, f: impl Fn(usize, usize) -> [u8; 4]) -> FramePixels {
    let mut rgba = Vec::with_capacity(usize::from(width) * usize::from(height) * 4);
    for y in 0..usize::from(height) {
        for x in 0..usize::from(width) {
            rgba.extend_from_slice(&f(x, y));
        }
    }
    FramePixels::new(width, height, rgba).unwrap()
}

fn decode_and_check(frame: &FramePixels) {
    let sample_count = if (frame.width, frame.height) == (3840, 2160) && !cfg!(debug_assertions) {
        20
    } else {
        1
    };
    let mut encode_samples = Vec::new();
    let mut measured_output_bytes = 0;
    for _ in 0..sample_count {
        let started = Instant::now();
        let measured = encode_tiles(frame, None).unwrap().unwrap();
        encode_samples.push(started.elapsed());
        measured_output_bytes = measured.payload.len();
        drop(measured);
    }
    encode_samples.sort_unstable();
    let p95 = encode_samples[(encode_samples.len() * 95).div_ceil(100) - 1];
    let encoded = encode_tiles(frame, None).unwrap().unwrap();
    assert_eq!(encoded.kind, FrameKind::Keyframe);
    assert_eq!(
        encoded.plans.len(),
        super::frame::tile_rects(frame.width, frame.height).count()
    );
    assert!(encoded.plans.len() <= MAX_TILE_COUNT);
    let tile_count = encoded.plans.len();
    assert!(
        encoded.plans.capacity() * std::mem::size_of::<super::TilePlan>() <= MAX_TILE_PLAN_BYTES
    );
    let payload_bound = (tile_count * MAX_TILE_PNG_BYTES).min(MAX_FRAME_PNG_BYTES);
    assert!(encoded.payload.capacity() <= payload_bound);
    assert!(encoded.payload.len() <= MAX_FRAME_PNG_BYTES);
    let mut expected_payload_offset = 0u32;
    let mut expected_tiles = super::frame::tile_rects(frame.width, frame.height);
    for plan in &encoded.plans {
        let expected_tile = expected_tiles.next().expect("one PNG per keyframe tile");
        assert_eq!(
            (plan.x, plan.y, plan.width, plan.height),
            (
                expected_tile.x,
                expected_tile.y,
                expected_tile.width,
                expected_tile.height
            )
        );
        assert_eq!(plan.payload_offset, expected_payload_offset);
        expected_payload_offset += plan.png_len;
        assert!(plan.png_len as usize <= MAX_TILE_PNG_BYTES);
        let start = plan.payload_offset as usize;
        let end = start + plan.png_len as usize;
        let mut decoder = png::Decoder::new(Cursor::new(&encoded.payload[start..end]));
        decoder.set_transformations(png::Transformations::IDENTITY);
        let mut reader = decoder.read_info().unwrap();
        let mut output = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut output).unwrap();
        assert_eq!(
            (info.width, info.height),
            (u32::from(plan.width), u32::from(plan.height))
        );
        assert_eq!(info.color_type, png::ColorType::Rgba);
        assert_eq!(info.bit_depth, png::BitDepth::Eight);
        let tile = super::frame::TileRect {
            x: plan.x,
            y: plan.y,
            width: plan.width,
            height: plan.height,
        };
        for row in 0..tile.height {
            let source = frame.tile_row(tile, tile.y + row);
            let start = usize::from(row) * usize::from(tile.width) * 4;
            assert_eq!(&output[start..start + source.len()], source);
        }
    }
    assert!(expected_tiles.next().is_none());
    assert_eq!(expected_payload_offset as usize, encoded.payload.len());
    if (frame.width, frame.height) == (3840, 2160) {
        eprintln!(
            "generated 4K RGBA codec sample (not native corpus): samples={} tiles={} output_bytes={} codec_p95_us={}",
            sample_count,
            encoded.plans.len(),
            measured_output_bytes,
            p95.as_micros()
        );
    }
}

#[test]
#[ignore = "run against captured native RGBA with CONMAN_STREAM_CORPUS_FRAME set"]
fn native_corpus_1920_reassembles_exactly_in_release_measurement() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("CONMAN_STREAM_CORPUS_FRAME").expect("corpus frame directory"),
    );
    let reference = std::fs::read(directory.join("reference.rgba")).unwrap();
    let manifest = std::fs::read_to_string(directory.join("manifest.json")).unwrap();
    let hash = manifest
        .split_once("\"reconstructed_rgba_sha256\": \"")
        .and_then(|(_, text)| text.split_once('"').map(|(hash, _)| hash))
        .expect("manifest reconstruction hash");
    let width = 1920u16;
    let height = 1080u16;
    assert_eq!(
        reference.len(),
        usize::from(width) * usize::from(height) * 4
    );
    let frame = FramePixels::new(width, height, reference.clone()).unwrap();
    let mut encode_samples = Vec::new();
    let mut output_bytes = 0;
    for _ in 0..20 {
        let started = Instant::now();
        let measured = encode_tiles(&frame, None).unwrap().unwrap();
        encode_samples.push(started.elapsed());
        output_bytes = measured.payload.len();
        drop(measured);
    }
    encode_samples.sort_unstable();
    let p95 = encode_samples[(encode_samples.len() * 95).div_ceil(100) - 1];
    let encoded = encode_tiles(&frame, None).unwrap().unwrap();
    let mut reconstructed = vec![0; reference.len()];
    for plan in &encoded.plans {
        let start = plan.payload_offset as usize;
        let end = start + plan.png_len as usize;
        let mut decoder = png::Decoder::new(Cursor::new(&encoded.payload[start..end]));
        decoder.set_transformations(png::Transformations::IDENTITY);
        let mut reader = decoder.read_info().unwrap();
        let decoded_len = reader.output_buffer_size().unwrap();
        assert!(decoded_len <= 64 * 64 * 4);
        let mut output = vec![0; decoded_len];
        let info = reader.next_frame(&mut output).unwrap();
        let tile = super::frame::TileRect {
            x: plan.x,
            y: plan.y,
            width: plan.width,
            height: plan.height,
        };
        assert_eq!(
            (info.width, info.height),
            (u32::from(tile.width), u32::from(tile.height))
        );
        for row in 0..tile.height {
            let source_start = usize::from(row) * usize::from(tile.width) * 4;
            let destination_start =
                (usize::from(tile.y + row) * usize::from(width) + usize::from(tile.x)) * 4;
            let row_len = usize::from(tile.width) * 4;
            reconstructed[destination_start..destination_start + row_len]
                .copy_from_slice(&output[source_start..source_start + row_len]);
        }
    }
    assert_eq!(reconstructed, reference);
    eprintln!(
        "native-corpus 1920x1080 sha256={hash} samples=20 tiles={} output_bytes={} codec_p95_us={}",
        encoded.plans.len(),
        output_bytes,
        p95.as_micros()
    );
}

#[test]
fn png_tiles_round_trip_at_tile_edges_and_4k() {
    for (width, height) in [(1, 1), (64, 64), (65, 65), (3840, 2160)] {
        decode_and_check(&pixels(width, height, |x, y| {
            [(x % 251) as u8, (y % 241) as u8, ((x ^ y) % 239) as u8, 255]
        }));
    }
}

#[test]
fn delta_encodes_only_changed_tiles_and_identical_frame_is_empty() {
    let base = pixels(130, 70, |_, _| [1, 2, 3, 255]);
    assert!(encode_tiles(&base, Some(&base)).unwrap().is_none());
    let changed = pixels(130, 70, |x, y| {
        if (64..128).contains(&x) && (0..64).contains(&y) {
            [8, 9, 10, 255]
        } else {
            [1, 2, 3, 255]
        }
    });
    let delta = encode_tiles(&changed, Some(&base)).unwrap().unwrap();
    assert_eq!(delta.kind, FrameKind::Delta);
    assert_eq!(delta.plans.len(), 1);
    assert_eq!((delta.plans[0].x, delta.plans[0].y), (64, 0));
}

#[test]
fn opaque_normalization_preserves_rgb_for_transparent_and_opaque_pixels() {
    let mut frame = FramePixels::new(2, 1, vec![12, 34, 56, 0, 78, 90, 123, 255]).unwrap();
    frame.normalize_opaque();
    assert_eq!(frame.rgba, [12, 34, 56, 255, 78, 90, 123, 255]);
    decode_and_check(&frame);
}

#[test]
fn png_caps_reject_partial_tiles_and_frames_without_returning_payload() {
    let frame = pixels(64, 64, |x, y| [(x * 7) as u8, (y * 11) as u8, 19, 255]);
    assert!(matches!(
        encode_tiles_with_limits(&frame, None, 1, usize::MAX),
        Err(StreamError::PngTileTooLarge)
    ));
    assert!(matches!(
        encode_tiles_with_limits(&frame, None, usize::MAX, 1),
        Err(StreamError::EncodedFrameTooLarge)
    ));
}

fn native(generation: u64, width: u16, height: u16, color: u8) -> NativeFrame {
    NativeFrame {
        generation,
        width,
        height,
        rgba: vec![color; usize::from(width) * usize::from(height) * 4],
    }
}

#[test]
fn frame_requires_ack_and_releases_payload_lease_before_next_prepare() {
    let now = Instant::now();
    let mut state = FrameState::new(7);
    assert_eq!(
        state.offer(native(7, 2, 2, 1), now).unwrap(),
        OfferResult::StoredLatest { replaced: false }
    );
    let first = state.prepare_next(now).unwrap().unwrap();
    let first_metadata = first.metadata();
    assert_eq!(first_metadata.kind, FrameKind::Keyframe);
    assert_eq!(first.tiles().len(), first_metadata.tile_count);
    assert_eq!(
        first.png_payload().len(),
        first_metadata.total_png_bytes as usize
    );
    let ack = FrameAck {
        generation: 7,
        epoch: first_metadata.epoch,
        sequence: first_metadata.sequence,
    };
    assert_eq!(state.acknowledge(ack, now).unwrap(), AckResult::Accepted);
    assert_eq!(state.acknowledge(ack, now).unwrap(), AckResult::Duplicate);
    state
        .offer(native(7, 2, 2, 3), now + FRAME_INTERVAL)
        .unwrap();
    assert!(state.prepare_next(now + FRAME_INTERVAL).unwrap().is_none());
    drop(first);
    let delta = state.prepare_next(now + FRAME_INTERVAL).unwrap().unwrap();
    assert_eq!(delta.metadata().kind, FrameKind::Delta);
    assert_eq!(delta.metadata().base_sequence, Some(ack.sequence));
    assert!(state.prepare_next(now + FRAME_INTERVAL).unwrap().is_none());
}

#[test]
fn wrong_generation_and_invalid_buffers_are_rejected() {
    let now = Instant::now();
    let mut state = FrameState::new(2);
    assert_eq!(
        state.offer(native(3, 1, 1, 0), now),
        Err(StreamError::StaleGeneration)
    );
    assert!(matches!(
        FramePixels::new(0, 1, Vec::new()),
        Err(StreamError::InvalidDimensions)
    ));
    assert!(matches!(
        FramePixels::new(1, 1, vec![0; 3]),
        Err(StreamError::InvalidRgbaLength)
    ));
    let oversized = vec![0; usize::from(MAX_WIDTH) * 2160 * 4 + 4];
    assert!(matches!(
        FramePixels::new(MAX_WIDTH, 2160, oversized),
        Err(StreamError::InvalidRgbaLength)
    ));
    let mut extra_capacity = Vec::with_capacity(8);
    extra_capacity.extend_from_slice(&[0; 4]);
    assert!(matches!(
        FramePixels::new(1, 1, extra_capacity),
        Err(StreamError::ResourceLimit)
    ));
}

#[test]
fn timeout_aborts_and_closes_after_three_consecutive_failures() {
    let start = Instant::now();
    let mut state = FrameState::new(9);
    for attempt in 0..3 {
        let now = start + FRAME_INTERVAL * attempt;
        state.offer(native(9, 1, 1, attempt as u8), now).unwrap();
        let prepared = state.prepare_next(now).unwrap().unwrap();
        let due = now + FRAME_ACK_TIMEOUT;
        let output = state.timeout(due).unwrap();
        let metadata = prepared.metadata();
        if attempt < 2 {
            assert_eq!(
                output,
                StreamOutput::Abort {
                    epoch: metadata.epoch,
                    sequence: metadata.sequence
                }
            );
        } else {
            assert_eq!(
                output,
                StreamOutput::Closed(super::state::StreamCloseReason::ResyncFailures)
            );
        }
        drop(prepared);
    }
    assert!(matches!(
        state.prepare_next(start + Duration::from_secs(20)),
        Err(StreamError::Closed)
    ));
}

#[test]
fn late_ack_returns_timeout_transition_and_third_failure_is_visible() {
    let start = Instant::now();
    let mut state = FrameState::new(23);
    state.offer(native(23, 1, 1, 1), start).unwrap();

    for attempt in 0..3 {
        let sent_at = start + FRAME_INTERVAL * attempt;
        let flight = state.prepare_next(sent_at).unwrap().unwrap();
        let metadata = flight.metadata();
        let result = state
            .acknowledge(
                FrameAck {
                    generation: 23,
                    epoch: metadata.epoch,
                    sequence: metadata.sequence,
                },
                sent_at + FRAME_ACK_TIMEOUT,
            )
            .unwrap();
        let expected = if attempt < 2 {
            StreamOutput::Abort {
                epoch: metadata.epoch,
                sequence: metadata.sequence,
            }
        } else {
            StreamOutput::Closed(super::state::StreamCloseReason::ResyncFailures)
        };
        assert_eq!(result, AckResult::TimedOut { output: expected });
        drop(flight);
    }
    assert_eq!(
        state.offer(native(23, 1, 1, 4), start + Duration::from_secs(20)),
        Err(StreamError::Closed)
    );
}

fn prepared(generation: u64) -> (FrameState, super::state::PreparedFrame, Instant) {
    let now = Instant::now();
    let mut state = FrameState::new(generation);
    state.offer(native(generation, 2, 2, 7), now).unwrap();
    let frame = state.prepare_next(now).unwrap().unwrap();
    (state, frame, now)
}

#[test]
fn acknowledgements_classify_stale_duplicate_future_wrong_generation_and_epoch() {
    let (mut state, first, now) = prepared(5);
    let metadata = first.metadata();
    let expected = FrameAck {
        generation: metadata.generation,
        epoch: metadata.epoch,
        sequence: metadata.sequence,
    };
    assert_eq!(
        state
            .acknowledge(
                FrameAck {
                    sequence: 0,
                    ..expected
                },
                now
            )
            .unwrap(),
        AckResult::Stale
    );
    assert_eq!(
        state.acknowledge(expected, now).unwrap(),
        AckResult::Accepted
    );
    assert_eq!(
        state.acknowledge(expected, now).unwrap(),
        AckResult::Duplicate
    );
    drop(first);

    for bad_ack in [
        FrameAck {
            generation: 6,
            ..expected
        },
        FrameAck {
            epoch: expected.epoch + 1,
            ..expected
        },
        FrameAck {
            sequence: expected.sequence + 1,
            ..expected
        },
    ] {
        let (mut state, flight, now) = prepared(5);
        assert_eq!(
            state.acknowledge(bad_ack, now),
            Err(StreamError::InvalidAck)
        );
        assert!(matches!(state.timeout(now), Ok(StreamOutput::Noop)));
        drop(flight);
    }
}

#[test]
fn last_ack_is_stale_while_a_newer_frame_is_in_flight() {
    let now = Instant::now();
    let mut state = FrameState::new(6);
    state.offer(native(6, 1, 1, 1), now).unwrap();
    let first = state.prepare_next(now).unwrap().unwrap();
    let first_metadata = first.metadata();
    let previous = FrameAck {
        generation: 6,
        epoch: first_metadata.epoch,
        sequence: first_metadata.sequence,
    };
    state.acknowledge(previous, now).unwrap();
    drop(first);
    let later = now + FRAME_INTERVAL;
    state.offer(native(6, 1, 1, 2), later).unwrap();
    let second = state.prepare_next(later).unwrap().unwrap();
    assert_eq!(
        state.acknowledge(previous, later).unwrap(),
        AckResult::Duplicate
    );
    let metadata = second.metadata();
    assert_eq!(
        state
            .acknowledge(
                FrameAck {
                    generation: 6,
                    epoch: metadata.epoch,
                    sequence: metadata.sequence,
                },
                later,
            )
            .unwrap(),
        AckResult::Accepted
    );
}

#[test]
fn acknowledgement_without_candidate_is_invalid_and_forces_resync() {
    let now = Instant::now();
    let mut state = FrameState::new(22);
    assert_eq!(
        state.acknowledge(
            FrameAck {
                generation: 22,
                epoch: 1,
                sequence: 1,
            },
            now,
        ),
        Err(StreamError::InvalidAck)
    );
    state.offer(native(22, 1, 1, 0), now).unwrap();
    let keyframe = state.prepare_next(now).unwrap().unwrap();
    assert_eq!(keyframe.metadata().kind, FrameKind::Keyframe);
    assert_eq!(keyframe.metadata().epoch, 1);
}

#[test]
fn resize_during_flight_waits_for_ack_then_starts_new_epoch_keyframe() {
    let now = Instant::now();
    let mut state = FrameState::new(11);
    state.offer(native(11, 2, 2, 1), now).unwrap();
    let first = state.prepare_next(now).unwrap().unwrap();
    let first_meta = first.metadata();
    state.offer(native(11, 3, 2, 2), now).unwrap();
    assert!(state.prepare_next(now + FRAME_INTERVAL).unwrap().is_none());
    state
        .acknowledge(
            FrameAck {
                generation: 11,
                epoch: first_meta.epoch,
                sequence: first_meta.sequence,
            },
            now,
        )
        .unwrap();
    drop(first);
    let resized = state.prepare_next(now + FRAME_INTERVAL).unwrap().unwrap();
    let metadata = resized.metadata();
    assert_eq!(metadata.kind, FrameKind::Keyframe);
    assert_eq!((metadata.width, metadata.height), (3, 2));
    assert_eq!(metadata.epoch, first_meta.epoch + 1);
}

#[test]
fn explicit_resync_forces_keyframe_and_invalid_acks_close_after_three_failures() {
    let now = Instant::now();
    let mut state = FrameState::new(13);
    state.offer(native(13, 1, 1, 1), now).unwrap();
    let first = state.prepare_next(now).unwrap().unwrap();
    let metadata = first.metadata();
    state
        .acknowledge(
            FrameAck {
                generation: 13,
                epoch: metadata.epoch,
                sequence: metadata.sequence,
            },
            now,
        )
        .unwrap();
    drop(first);
    state
        .offer(native(13, 1, 1, 2), now + FRAME_INTERVAL)
        .unwrap();
    state
        .abort_and_resync(super::state::ResyncReason::Explicit)
        .unwrap();
    let resync = state.prepare_next(now + FRAME_INTERVAL).unwrap().unwrap();
    assert_eq!(resync.metadata().kind, FrameKind::Keyframe);
    assert_eq!(resync.metadata().epoch, metadata.epoch + 1);
    drop(resync);

    let start = Instant::now();
    let mut state = FrameState::new(14);
    state.offer(native(14, 1, 1, 1), start).unwrap();
    for attempt in 0..3 {
        let at = start + FRAME_INTERVAL * attempt;
        let flight = state.prepare_next(at).unwrap().unwrap();
        let metadata = flight.metadata();
        let bad = FrameAck {
            generation: 14,
            epoch: metadata.epoch,
            sequence: metadata.sequence + 1,
        };
        let result = state.acknowledge(bad, at);
        if attempt < 2 {
            assert_eq!(result, Err(StreamError::InvalidAck));
        } else {
            assert_eq!(result, Err(StreamError::ResyncFailures));
        }
        drop(flight);
    }
    assert_eq!(
        state.offer(native(14, 1, 1, 3), start),
        Err(StreamError::Closed)
    );
}

#[test]
fn epoch_and_sequence_exhaustion_close_state_before_future_offers() {
    for (epoch, next_sequence, expected) in [
        (u64::MAX, Some(1), StreamError::EpochExhausted),
        (0, None, StreamError::SequenceExhausted),
    ] {
        let now = Instant::now();
        let mut state = FrameState::new(21);
        state.offer(native(21, 1, 1, 0), now).unwrap();
        state.set_counters_for_test(epoch, next_sequence);
        assert!(matches!(state.prepare_next(now), Err(error) if error == expected));
        assert_eq!(
            state.offer(native(21, 1, 1, 0), now),
            Err(StreamError::Closed)
        );
    }
}

#[test]
fn four_k_offers_replace_one_latest_slot_with_exact_frame_capacities() {
    let now = Instant::now();
    let bytes = 3840usize * 2160 * 4;
    let mut state = FrameState::new(15);
    state.offer(native(15, 3840, 2160, 1), now).unwrap();
    let first = state.prepare_next(now).unwrap().unwrap();
    let first_meta = first.metadata();
    state
        .acknowledge(
            FrameAck {
                generation: 15,
                epoch: first_meta.epoch,
                sequence: first_meta.sequence,
            },
            now,
        )
        .unwrap();
    drop(first);
    let later = now + FRAME_INTERVAL;
    state.offer(native(15, 3840, 2160, 2), later).unwrap();
    let flight = state.prepare_next(later).unwrap().unwrap();
    for color in 3..=6 {
        assert_eq!(
            state.offer(native(15, 3840, 2160, color), later),
            Ok(OfferResult::AwaitingAck)
        );
        assert_eq!(
            state.retained_frame_capacities_for_test(),
            (Some(bytes), Some(bytes), Some(bytes))
        );
    }
    let flight_meta = flight.metadata();
    state
        .acknowledge(
            FrameAck {
                generation: 15,
                epoch: flight_meta.epoch,
                sequence: flight_meta.sequence,
            },
            later,
        )
        .unwrap();
    assert_eq!(
        state.retained_frame_capacities_for_test(),
        (Some(bytes), None, Some(bytes))
    );
    assert!(
        state
            .prepare_next(later + FRAME_INTERVAL)
            .unwrap()
            .is_none()
    );
    drop(flight);
    let latest = state.prepare_next(later + FRAME_INTERVAL).unwrap().unwrap();
    assert_eq!(latest.metadata().kind, FrameKind::Delta);
}

#[test]
fn reservation_matches_frozen_formula_and_rejects_over_tile_limit() {
    let reserved = codec_reservation_bytes(3840, 2160).unwrap();
    let frame = 3840usize * 2160 * 4;
    let plans = 24 + 16 * 2040;
    let payload = 2040 * 20 * 1024;
    assert_eq!(reserved, 4 * frame + payload + plans + 256 + 16 * 1024);
    assert_eq!(
        codec_reservation_bytes(0, 4),
        Err(StreamError::InvalidDimensions)
    );
}
