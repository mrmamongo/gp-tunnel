#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    globalprotect_remote_gui_lib::run();
}
