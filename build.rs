fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)
        .compile_protos(
            &[
                "proto/jito/shredstream.proto",
                "proto/jito/auth.proto",
                "proto/yellowstone/geyser.proto",
            ],
            &["proto/jito", "proto/yellowstone"],
        )?;
    Ok(())
}
