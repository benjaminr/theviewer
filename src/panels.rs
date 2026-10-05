//! State for the tool panels that keep their own, and how they are drawn.
//!
//! Each of these panels lives in its own `panel_*` module with a state struct
//! and a `show` function taking that state and the app. The states are kept
//! together here, in the app's workbench, and lent to the panel each frame.

use eframe::egui::Ui;

use crate::app::ViewerApp;
use crate::panel_bits::BitsState;
use crate::panel_compare::CompareState;
use crate::panel_forensics::ForensicsState;
use crate::panel_crypto::CryptoState;

/// The state of every self-contained tool panel.
#[derive(Default)]
pub struct PanelStates {
    pub crypto: CryptoState,
    pub compare: CompareState,
    pub bits: BitsState,
    pub forensics: ForensicsState,
}

/// Draw a panel, lending it its state from `app` for the frame. The state is
/// taken out while the panel runs, so the panel can also borrow the app.
pub fn show<S: Default>(
    app: &mut ViewerApp,
    ui: &mut Ui,
    slot: fn(&mut PanelStates) -> &mut S,
    draw: fn(&mut S, &mut ViewerApp, &mut Ui),
) {
    let mut state = std::mem::take(slot(&mut app.bench.panels));
    draw(&mut state, app, ui);
    *slot(&mut app.bench.panels) = state;
}
