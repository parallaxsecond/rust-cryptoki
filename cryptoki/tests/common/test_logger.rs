// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Log capture infrastructure for tests.
#![allow(dead_code)]

use log::{Level, LevelFilter, Metadata, Record};
use std::sync::Mutex;

static LOG_MESSAGES: Mutex<Vec<(Level, String)>> = Mutex::new(Vec::new());
static LOGGER: TestLogger = TestLogger;

struct TestLogger;

impl log::Log for TestLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            if let Ok(mut logs) = LOG_MESSAGES.lock() {
                logs.push((record.level(), format!("{}", record.args())));
            }
        }
    }

    fn flush(&self) {}
}

pub fn init_logger() {
    // Ignore error if already initialized
    let _ = log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Warn));
}

pub fn clear_logs() {
    if let Ok(mut logs) = LOG_MESSAGES.lock() {
        logs.clear();
    }
}

pub fn get_logs() -> Vec<(Level, String)> {
    LOG_MESSAGES
        .lock()
        .map(|logs| logs.clone())
        .unwrap_or_default()
}

pub fn logs_contain_warning(substring: &str) -> bool {
    get_logs()
        .iter()
        .any(|(l, msg)| *l == Level::Warn && msg.contains(substring))
}

pub fn print_logs() {
    for (level, msg) in get_logs() {
        println!("  [{:?}] {}", level, msg);
    }
}
