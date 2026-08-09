use nodavo_platform_macos::{accessibility_trusted, active_displays};

fn main() {
    println!("accessibility_trusted={}", accessibility_trusted());
    match active_displays() {
        Ok(displays) => {
            println!("active_displays={}", displays.len());
            for display in displays {
                println!(
                    "display points={}x{} pixels={}x{}",
                    display.width_points,
                    display.height_points,
                    display.width_pixels,
                    display.height_pixels
                );
            }
        }
        Err(error) => {
            eprintln!("display_probe_failed={error}");
            std::process::exit(1);
        }
    }
}
