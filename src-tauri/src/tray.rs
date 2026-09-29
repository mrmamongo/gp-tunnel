use crate::{request_stop, AppState};
use std::sync::Mutex;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, LogicalSize, Manager, PhysicalPosition, WindowEvent,
};

#[derive(Clone, Copy, Default)]
struct Anchor {
    x: i32,
    y: i32,
    width: i32,
    height: i32,
}
#[derive(Default)]
pub(crate) struct PanelState {
    anchor: Mutex<Option<Anchor>>,
    height: Mutex<f64>,
}

fn work_area(anchor: Anchor) -> (i32, i32, i32, i32) {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::{
            Foundation::POINT,
            Graphics::Gdi::{
                GetMonitorInfoW, MonitorFromPoint, MONITORINFO, MONITOR_DEFAULTTONEAREST,
            },
        };
        let monitor = MonitorFromPoint(
            POINT {
                x: anchor.x,
                y: anchor.y,
            },
            MONITOR_DEFAULTTONEAREST,
        );
        let mut info: MONITORINFO = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
        if GetMonitorInfoW(monitor, &mut info) != 0 {
            let r = info.rcWork;
            return (r.left, r.top, r.right, r.bottom);
        }
    }
    (0, 0, 1920, 1080)
}
fn position(
    anchor: Anchor,
    bounds: (i32, i32, i32, i32),
    width: i32,
    height: i32,
    gap: i32,
) -> (i32, i32) {
    let (left, top, right, bottom) = bounds;
    let x = anchor.x + anchor.width - width;
    let y = if anchor.y - height - gap >= top {
        anchor.y - height - gap
    } else if anchor.y + anchor.height + height + gap <= bottom {
        anchor.y + anchor.height + gap
    } else {
        anchor.y + anchor.height / 2 - height / 2
    };
    let x = if anchor.x < left {
        left + gap
    } else if anchor.x >= right {
        right - width - gap
    } else {
        x
    };
    (
        x.clamp(left + gap, (right - width - gap).max(left + gap)),
        y.clamp(top + gap, (bottom - height - gap).max(top + gap)),
    )
}
fn place(app: &AppHandle) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let panel = app.state::<PanelState>();
    let anchor = (*panel.anchor.lock().unwrap()).unwrap_or_else(|| {
        let monitor = window.primary_monitor().ok().flatten();
        monitor
            .map(|m| Anchor {
                x: m.position().x + m.size().width as i32 - 16,
                y: m.position().y + m.size().height as i32 - 32,
                width: 16,
                height: 16,
            })
            .unwrap_or(Anchor {
                x: 1900,
                y: 1040,
                width: 16,
                height: 16,
            })
    });
    let bounds = work_area(anchor);
    let scale = window
        .available_monitors()
        .unwrap_or_default()
        .into_iter()
        .find(|m| {
            anchor.x >= m.position().x
                && anchor.y >= m.position().y
                && anchor.x < m.position().x + m.size().width as i32
                && anchor.y < m.position().y + m.size().height as i32
        })
        .map(|m| m.scale_factor())
        .unwrap_or(1.0);
    let desired = *panel.height.lock().unwrap();
    let gap = (8.0 * scale).round() as i32;
    let width = (340.0 * scale)
        .round()
        .min((bounds.2 - bounds.0 - gap * 2) as f64) as i32;
    let height = (desired.max(260.0) * scale)
        .round()
        .min((bounds.3 - bounds.1 - gap * 2) as f64) as i32;
    let (x, y) = position(anchor, bounds, width, height, gap);
    let _ = window.set_position(PhysicalPosition::new(x, y));
    let _ = window.set_size(LogicalSize::new(
        width as f64 / scale,
        height as f64 / scale,
    ));
}
pub(crate) fn show(app: &AppHandle) {
    place(app);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
        let _ = window.emit("panel://shown", ());
    }
}
#[tauri::command]
pub(crate) fn panel_hide(app: AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.hide();
    }
}
#[tauri::command]
pub(crate) fn panel_resize(app: AppHandle, height: f64) {
    if !height.is_finite() {
        return;
    }
    *app.state::<PanelState>().height.lock().unwrap() = height.clamp(260.0, 900.0);
    place(&app);
}
fn cursor_on_tray(app: &AppHandle) -> bool {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::{Foundation::POINT, UI::WindowsAndMessaging::GetCursorPos};
        let mut cursor = POINT { x: 0, y: 0 };
        if GetCursorPos(&mut cursor) != 0 {
            if let Some(a) = *app.state::<PanelState>().anchor.lock().unwrap() {
                return cursor.x >= a.x
                    && cursor.x < a.x + a.width
                    && cursor.y >= a.y
                    && cursor.y < a.y + a.height;
            }
        }
    }
    false
}
pub(crate) fn window_event(window: &tauri::Window, event: &WindowEvent) {
    match event {
        WindowEvent::CloseRequested { api, .. } => {
            api.prevent_close();
            let _ = window.hide();
        }
        WindowEvent::Focused(false) => {
            if !cursor_on_tray(window.app_handle()) {
                let _ = window.hide();
            }
        }
        WindowEvent::ScaleFactorChanged { .. } => {
            place(window.app_handle());
        }
        _ => {}
    }
}
fn icon(color: [u8; 3]) -> tauri::image::Image<'static> {
    // Crisp small ring with a solid status dot; no runtime image dependency.
    let size = 32usize;
    let mut data = vec![0u8; size * size * 4];
    for y in 0..size {
        for x in 0..size {
            let d = ((x as f64 - 15.5).powi(2) + (y as f64 - 15.5).powi(2)).sqrt();
            if (9.0..13.0).contains(&d) || d < 4.0 {
                let i = (y * size + x) * 4;
                data[i..i + 3].copy_from_slice(&color);
                data[i + 3] = 255;
            }
        }
    }
    tauri::image::Image::new_owned(data, size as u32, size as u32)
}
pub(crate) fn refresh(app: &AppHandle) {
    let app = app.clone();
    let dispatcher = app.clone();
    let _ = dispatcher.run_on_main_thread(move || {
        let state = app.state::<AppState>();
        let snapshot = state.inner.lock().unwrap().snapshot.clone();
        let Some(tray) = app.tray_by_id("relay") else {
            return;
        };
        let color = if snapshot.prompt.is_some() {
            [221, 154, 34]
        } else {
            match snapshot.state.as_str() {
                "connected" => [42, 166, 99],
                "error" => [219, 72, 72],
                "preparing" | "connecting" | "disconnecting" => [56, 132, 240],
                _ => [137, 145, 155],
            }
        };
        let _ = tray.set_icon(Some(icon(color)));
        let tip = if snapshot.prompt.is_some() {
            format!("GP Relay {} · Ожидается ввод", app.package_info().version)
        } else {
            format!(
                "GP Relay {} · {}",
                app.package_info().version,
                snapshot.message.chars().take(100).collect::<String>()
            )
        };
        let _ = tray.set_tooltip(Some(tip));
        if let Some(item) = app.try_state::<DisconnectMenu>() {
            let _ = item
                .0
                .set_enabled(snapshot.active || snapshot.cleanup_required);
        }
    });
}
struct DisconnectMenu(MenuItem<tauri::Wry>);
pub(crate) fn setup(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Открыть", true, None::<&str>)?;
    let disconnect = MenuItem::with_id(app, "disconnect", "Отключить", false, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Выйти", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &disconnect, &quit])?;
    app.manage(DisconnectMenu(disconnect));
    TrayIconBuilder::with_id("relay")
        .icon(icon([137, 145, 155]))
        .tooltip(format!(
            "GP Relay {} · Не подключён",
            app.package_info().version
        ))
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show(app),
            "disconnect" => request_stop(app, &app.state::<AppState>(), false),
            "quit" => request_stop(app, &app.state::<AppState>(), true),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button,
                button_state: MouseButtonState::Up,
                rect,
                ..
            } = event
            {
                let app = tray.app_handle();
                let Some(window) = app.get_webview_window("main") else {
                    return;
                };
                let scale = window.scale_factor().unwrap_or(1.0);
                let pos = rect.position.to_physical::<i32>(scale);
                let size = rect.size.to_physical::<u32>(scale);
                *app.state::<PanelState>().anchor.lock().unwrap() = Some(Anchor {
                    x: pos.x,
                    y: pos.y,
                    width: size.width as i32,
                    height: size.height as i32,
                });
                if button == MouseButton::Left {
                    if window.is_visible().unwrap_or(false) {
                        let _ = window.hide();
                    } else {
                        show(app);
                    }
                } else if button == MouseButton::Right {
                    let _ = window.hide();
                }
            }
        })
        .build(app)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn popup_stays_in_work_area() {
        for bounds in [(0, 0, 1920, 1040), (-1920, 0, 0, 1040), (0, 0, 2560, 1400)] {
            for a in [
                Anchor {
                    x: bounds.2 - 24,
                    y: bounds.3,
                    width: 24,
                    height: 24,
                },
                Anchor {
                    x: bounds.0,
                    y: bounds.1 - 24,
                    width: 24,
                    height: 24,
                },
                Anchor {
                    x: bounds.0 - 24,
                    y: 400,
                    width: 24,
                    height: 24,
                },
            ] {
                for scale in [1, 2] {
                    let (w, h) = (340 * scale, 400 * scale);
                    let (x, y) = position(a, bounds, w, h, 8);
                    assert!(x >= bounds.0 && y >= bounds.1);
                    assert!(x + w <= bounds.2 && y + h <= bounds.3);
                }
            }
        }
    }
}
