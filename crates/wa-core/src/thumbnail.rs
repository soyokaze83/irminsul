use crate::{CoreError, CoreResult};
use bytes::Bytes;
use image::codecs::jpeg::JpegEncoder;
use image::imageops::FilterType;
use image::{DynamicImage, GenericImageView, ImageReader, Limits, RgbImage};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const DEFAULT_MAX_IMAGE_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_IMAGE_DIMENSION: u32 = 4096;
pub const DEFAULT_IMAGE_DECODE_MAX_ALLOC_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MESSAGE_THUMBNAIL_EDGE: u32 = 32;
pub const DEFAULT_PROFILE_PICTURE_EDGE: u32 = 640;
pub const DEFAULT_PROFILE_PICTURE_PREVIEW_EDGE: u32 = 96;
pub const DEFAULT_LINK_PREVIEW_INLINE_THUMBNAIL_EDGE: u32 = DEFAULT_MESSAGE_THUMBNAIL_EDGE;
pub const DEFAULT_LINK_PREVIEW_THUMBNAIL_EDGE: u32 = 512;
pub const DEFAULT_MESSAGE_THUMBNAIL_JPEG_QUALITY: u8 = 80;
pub const DEFAULT_PROFILE_PICTURE_JPEG_QUALITY: u8 = 100;
pub const DEFAULT_LINK_PREVIEW_INLINE_THUMBNAIL_JPEG_QUALITY: u8 =
    DEFAULT_MESSAGE_THUMBNAIL_JPEG_QUALITY;
pub const DEFAULT_LINK_PREVIEW_THUMBNAIL_JPEG_QUALITY: u8 = 85;
pub const DEFAULT_VIDEO_THUMBNAIL_COMMAND: &str = "ffmpeg";
pub const DEFAULT_VIDEO_THUMBNAIL_SEEK_TIME: &str = "00:00:00";
pub const DEFAULT_PDF_THUMBNAIL_COMMAND: &str = "pdftoppm";
pub const DEFAULT_PDF_THUMBNAIL_PAGE: u32 = 1;
pub const DEFAULT_PDF_THUMBNAIL_DPI: u32 = 72;
pub const DEFAULT_MAX_PDF_THUMBNAIL_DPI: u32 = 1200;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageProcessingLimits {
    pub max_input_bytes: usize,
    pub max_width: u32,
    pub max_height: u32,
    pub max_decode_alloc_bytes: u64,
}

impl Default for ImageProcessingLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_IMAGE_INPUT_BYTES,
            max_width: DEFAULT_MAX_IMAGE_DIMENSION,
            max_height: DEFAULT_MAX_IMAGE_DIMENSION,
            max_decode_alloc_bytes: DEFAULT_IMAGE_DECODE_MAX_ALLOC_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JpegThumbnailOptions {
    pub max_width: u32,
    pub max_height: u32,
    pub quality: u8,
    pub limits: ImageProcessingLimits,
}

impl Default for JpegThumbnailOptions {
    fn default() -> Self {
        Self {
            max_width: DEFAULT_MESSAGE_THUMBNAIL_EDGE,
            max_height: DEFAULT_MESSAGE_THUMBNAIL_EDGE,
            quality: DEFAULT_MESSAGE_THUMBNAIL_JPEG_QUALITY,
            limits: ImageProcessingLimits::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfilePictureOptions {
    pub image_size: u32,
    pub preview_size: u32,
    pub quality: u8,
    pub limits: ImageProcessingLimits,
}

impl Default for ProfilePictureOptions {
    fn default() -> Self {
        Self {
            image_size: DEFAULT_PROFILE_PICTURE_EDGE,
            preview_size: DEFAULT_PROFILE_PICTURE_PREVIEW_EDGE,
            quality: DEFAULT_PROFILE_PICTURE_JPEG_QUALITY,
            limits: ImageProcessingLimits::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkPreviewImageOptions {
    pub inline_max_width: u32,
    pub inline_max_height: u32,
    pub high_quality_max_width: u32,
    pub high_quality_max_height: u32,
    pub inline_quality: u8,
    pub high_quality_quality: u8,
    pub limits: ImageProcessingLimits,
}

impl Default for LinkPreviewImageOptions {
    fn default() -> Self {
        Self {
            inline_max_width: DEFAULT_LINK_PREVIEW_INLINE_THUMBNAIL_EDGE,
            inline_max_height: DEFAULT_LINK_PREVIEW_INLINE_THUMBNAIL_EDGE,
            high_quality_max_width: DEFAULT_LINK_PREVIEW_THUMBNAIL_EDGE,
            high_quality_max_height: DEFAULT_LINK_PREVIEW_THUMBNAIL_EDGE,
            inline_quality: DEFAULT_LINK_PREVIEW_INLINE_THUMBNAIL_JPEG_QUALITY,
            high_quality_quality: DEFAULT_LINK_PREVIEW_THUMBNAIL_JPEG_QUALITY,
            limits: ImageProcessingLimits::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VideoThumbnailOptions {
    pub ffmpeg_path: PathBuf,
    pub seek_time: String,
    pub output: JpegThumbnailOptions,
    pub temp_dir: Option<PathBuf>,
}

impl Default for VideoThumbnailOptions {
    fn default() -> Self {
        Self {
            ffmpeg_path: PathBuf::from(DEFAULT_VIDEO_THUMBNAIL_COMMAND),
            seek_time: DEFAULT_VIDEO_THUMBNAIL_SEEK_TIME.to_owned(),
            output: JpegThumbnailOptions::default(),
            temp_dir: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PdfThumbnailOptions {
    pub pdftoppm_path: PathBuf,
    pub page: u32,
    pub dpi: u32,
    pub output: JpegThumbnailOptions,
    pub temp_dir: Option<PathBuf>,
}

impl Default for PdfThumbnailOptions {
    fn default() -> Self {
        Self {
            pdftoppm_path: PathBuf::from(DEFAULT_PDF_THUMBNAIL_COMMAND),
            page: DEFAULT_PDF_THUMBNAIL_PAGE,
            dpi: DEFAULT_PDF_THUMBNAIL_DPI,
            output: JpegThumbnailOptions::default(),
            temp_dir: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedJpegThumbnail {
    pub jpeg: Bytes,
    pub source_width: u32,
    pub source_height: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedProfilePicture {
    pub image: Bytes,
    pub preview: Bytes,
    pub source_width: u32,
    pub source_height: u32,
    pub image_size: u32,
    pub preview_size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedLinkPreviewImages {
    pub jpeg_thumbnail: Bytes,
    pub high_quality_jpeg: Bytes,
    pub source_width: u32,
    pub source_height: u32,
    pub thumbnail_width: u32,
    pub thumbnail_height: u32,
    pub high_quality_width: u32,
    pub high_quality_height: u32,
}

pub fn generate_jpeg_thumbnail(
    input: &[u8],
    options: JpegThumbnailOptions,
) -> CoreResult<GeneratedJpegThumbnail> {
    validate_resize_box("thumbnail", options.max_width, options.max_height)?;
    validate_jpeg_quality(options.quality)?;
    let image = decode_image(input, options.limits)?;
    let (source_width, source_height) = image.dimensions();
    let (width, height) = fit_dimensions(
        source_width,
        source_height,
        options.max_width,
        options.max_height,
    );
    let resized = if width == source_width && height == source_height {
        image
    } else {
        image.resize(width, height, FilterType::Triangle)
    };
    let jpeg = encode_jpeg_rgb(&resized.to_rgb8(), options.quality)?;
    Ok(GeneratedJpegThumbnail {
        jpeg,
        source_width,
        source_height,
        width,
        height,
    })
}

pub fn generate_link_preview_images(
    input: &[u8],
    options: LinkPreviewImageOptions,
) -> CoreResult<GeneratedLinkPreviewImages> {
    validate_resize_box(
        "link preview inline thumbnail",
        options.inline_max_width,
        options.inline_max_height,
    )?;
    validate_resize_box(
        "link preview high quality thumbnail",
        options.high_quality_max_width,
        options.high_quality_max_height,
    )?;
    validate_jpeg_quality(options.inline_quality)?;
    validate_jpeg_quality(options.high_quality_quality)?;

    let image = decode_image(input, options.limits)?;
    let (source_width, source_height) = image.dimensions();
    let (thumbnail_width, thumbnail_height) = fit_dimensions(
        source_width,
        source_height,
        options.inline_max_width,
        options.inline_max_height,
    );
    let (high_quality_width, high_quality_height) = fit_dimensions(
        source_width,
        source_height,
        options.high_quality_max_width,
        options.high_quality_max_height,
    );

    let jpeg_thumbnail = aspect_fit_jpeg(
        &image,
        thumbnail_width,
        thumbnail_height,
        options.inline_quality,
        FilterType::Triangle,
    )?;
    let high_quality_jpeg = aspect_fit_jpeg(
        &image,
        high_quality_width,
        high_quality_height,
        options.high_quality_quality,
        FilterType::Lanczos3,
    )?;

    Ok(GeneratedLinkPreviewImages {
        jpeg_thumbnail,
        high_quality_jpeg,
        source_width,
        source_height,
        thumbnail_width,
        thumbnail_height,
        high_quality_width,
        high_quality_height,
    })
}

pub fn generate_profile_picture(
    input: &[u8],
    options: ProfilePictureOptions,
) -> CoreResult<GeneratedProfilePicture> {
    validate_square_size("profile picture image", options.image_size)?;
    validate_square_size("profile picture preview", options.preview_size)?;
    validate_jpeg_quality(options.quality)?;
    let image = decode_image(input, options.limits)?;
    let (source_width, source_height) = image.dimensions();
    let cropped = center_square_crop(&image)?;
    let image = square_jpeg(&cropped, options.image_size, options.quality)?;
    let preview = square_jpeg(&cropped, options.preview_size, options.quality)?;
    Ok(GeneratedProfilePicture {
        image,
        preview,
        source_width,
        source_height,
        image_size: options.image_size,
        preview_size: options.preview_size,
    })
}

pub fn generate_video_thumbnail_from_file(
    path: impl AsRef<Path>,
    options: VideoThumbnailOptions,
) -> CoreResult<GeneratedJpegThumbnail> {
    let path = path.as_ref();
    validate_video_thumbnail_options(path, &options)?;

    let temp_dir = options.temp_dir.clone().unwrap_or_else(std::env::temp_dir);
    std::fs::create_dir_all(&temp_dir)?;
    let output_path = temp_dir.join(format!(
        "wa-core-video-thumbnail-{}.jpg",
        rand::random::<u128>()
    ));
    let scale_filter = ffmpeg_scale_filter(options.output.max_width, options.output.max_height);
    let output = Command::new(&options.ffmpeg_path)
        .arg("-ss")
        .arg(&options.seek_time)
        .arg("-i")
        .arg(path)
        .arg("-y")
        .arg("-vf")
        .arg(scale_filter)
        .arg("-vframes")
        .arg("1")
        .arg("-f")
        .arg("image2")
        .arg(&output_path)
        .output()
        .map_err(|error| {
            CoreError::Task(format!("failed to run ffmpeg thumbnail command: {error}"))
        })?;

    if !output.status.success() {
        let _ = std::fs::remove_file(&output_path);
        return Err(CoreError::Task(format!(
            "ffmpeg thumbnail command failed with status {}{}",
            output.status,
            stderr_suffix(&output.stderr)
        )));
    }

    let frame = std::fs::read(&output_path).map_err(|error| {
        CoreError::Payload(format!(
            "ffmpeg thumbnail output could not be read: {error}"
        ))
    })?;
    let _ = std::fs::remove_file(&output_path);
    generate_jpeg_thumbnail(&frame, options.output)
}

pub fn generate_pdf_thumbnail_from_file(
    path: impl AsRef<Path>,
    options: PdfThumbnailOptions,
) -> CoreResult<GeneratedJpegThumbnail> {
    let path = path.as_ref();
    validate_pdf_thumbnail_options(path, &options)?;

    let temp_dir = options.temp_dir.clone().unwrap_or_else(std::env::temp_dir);
    std::fs::create_dir_all(&temp_dir)?;
    let output_prefix = temp_dir.join(format!("wa-core-pdf-thumbnail-{}", rand::random::<u128>()));
    let output_path = output_prefix.with_extension("jpg");
    let page = options.page.to_string();
    let dpi = options.dpi.to_string();
    let output = Command::new(&options.pdftoppm_path)
        .arg("-f")
        .arg(&page)
        .arg("-l")
        .arg(&page)
        .arg("-singlefile")
        .arg("-jpeg")
        .arg("-r")
        .arg(&dpi)
        .arg(path)
        .arg(&output_prefix)
        .output()
        .map_err(|error| {
            CoreError::Task(format!("failed to run PDF thumbnail command: {error}"))
        })?;

    if !output.status.success() {
        let _ = std::fs::remove_file(&output_path);
        return Err(CoreError::Task(format!(
            "PDF thumbnail command failed with status {}{}",
            output.status,
            stderr_suffix(&output.stderr)
        )));
    }

    let frame = std::fs::read(&output_path).map_err(|error| {
        CoreError::Payload(format!("PDF thumbnail output could not be read: {error}"))
    })?;
    let _ = std::fs::remove_file(&output_path);
    generate_jpeg_thumbnail(&frame, options.output)
}

fn decode_image(input: &[u8], limits: ImageProcessingLimits) -> CoreResult<DynamicImage> {
    validate_image_input(input, limits.max_input_bytes)?;
    let mut reader = ImageReader::new(Cursor::new(input))
        .with_guessed_format()
        .map_err(|error| CoreError::Payload(format!("image format detection failed: {error}")))?;
    let mut image_limits = Limits::default();
    image_limits.max_image_width = Some(limits.max_width);
    image_limits.max_image_height = Some(limits.max_height);
    image_limits.max_alloc = Some(limits.max_decode_alloc_bytes);
    reader.limits(image_limits);
    reader
        .decode()
        .map_err(|error| CoreError::Payload(format!("image decode failed: {error}")))
}

fn validate_image_input(input: &[u8], max_input_bytes: usize) -> CoreResult<()> {
    if input.is_empty() {
        return Err(CoreError::Payload(
            "image input must not be empty".to_owned(),
        ));
    }
    if max_input_bytes == 0 {
        return Err(CoreError::Payload(
            "image input byte limit must be greater than zero".to_owned(),
        ));
    }
    if input.len() > max_input_bytes {
        return Err(CoreError::Payload(format!(
            "image input is {} bytes, exceeding limit {max_input_bytes}",
            input.len()
        )));
    }
    Ok(())
}

fn validate_resize_box(label: &str, width: u32, height: u32) -> CoreResult<()> {
    if width == 0 || height == 0 {
        return Err(CoreError::Payload(format!(
            "{label} dimensions must be greater than zero"
        )));
    }
    validate_jpeg_dimension(label, width)?;
    validate_jpeg_dimension(label, height)
}

fn validate_square_size(label: &str, size: u32) -> CoreResult<()> {
    if size == 0 {
        return Err(CoreError::Payload(format!(
            "{label} size must be greater than zero"
        )));
    }
    validate_jpeg_dimension(label, size)
}

fn validate_jpeg_dimension(label: &str, size: u32) -> CoreResult<()> {
    if size > u16::MAX as u32 {
        return Err(CoreError::Payload(format!(
            "{label} dimension {size} exceeds JPEG encoder limit {}",
            u16::MAX
        )));
    }
    Ok(())
}

fn validate_jpeg_quality(quality: u8) -> CoreResult<()> {
    if quality == 0 || quality > 100 {
        return Err(CoreError::Payload(
            "JPEG quality must be between 1 and 100".to_owned(),
        ));
    }
    Ok(())
}

fn validate_video_thumbnail_options(
    path: &Path,
    options: &VideoThumbnailOptions,
) -> CoreResult<()> {
    if path.as_os_str().is_empty() {
        return Err(CoreError::Payload(
            "video thumbnail input path must not be empty".to_owned(),
        ));
    }
    if options.ffmpeg_path.as_os_str().is_empty() {
        return Err(CoreError::Payload(
            "video thumbnail ffmpeg path must not be empty".to_owned(),
        ));
    }
    if options.seek_time.trim().is_empty() {
        return Err(CoreError::Payload(
            "video thumbnail seek time must not be empty".to_owned(),
        ));
    }
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(CoreError::Payload(
            "video thumbnail input path must be a regular file".to_owned(),
        ));
    }
    validate_resize_box(
        "video thumbnail",
        options.output.max_width,
        options.output.max_height,
    )?;
    validate_jpeg_quality(options.output.quality)
}

fn validate_pdf_thumbnail_options(path: &Path, options: &PdfThumbnailOptions) -> CoreResult<()> {
    if path.as_os_str().is_empty() {
        return Err(CoreError::Payload(
            "PDF thumbnail input path must not be empty".to_owned(),
        ));
    }
    if options.pdftoppm_path.as_os_str().is_empty() {
        return Err(CoreError::Payload(
            "PDF thumbnail command path must not be empty".to_owned(),
        ));
    }
    if options.page == 0 {
        return Err(CoreError::Payload(
            "PDF thumbnail page must be greater than zero".to_owned(),
        ));
    }
    if options.dpi == 0 || options.dpi > DEFAULT_MAX_PDF_THUMBNAIL_DPI {
        return Err(CoreError::Payload(format!(
            "PDF thumbnail DPI must be between 1 and {DEFAULT_MAX_PDF_THUMBNAIL_DPI}"
        )));
    }
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(CoreError::Payload(
            "PDF thumbnail input path must be a regular file".to_owned(),
        ));
    }
    validate_resize_box(
        "PDF thumbnail",
        options.output.max_width,
        options.output.max_height,
    )?;
    validate_jpeg_quality(options.output.quality)
}

fn stderr_suffix(stderr: &[u8]) -> String {
    if stderr.is_empty() {
        return String::new();
    }
    let message = String::from_utf8_lossy(stderr);
    let trimmed = message.trim();
    if trimmed.is_empty() {
        String::new()
    } else {
        format!(": {trimmed}")
    }
}

fn ffmpeg_scale_filter(max_width: u32, max_height: u32) -> String {
    format!(
        "scale=w=min({max_width}\\,iw):h=min({max_height}\\,ih):force_original_aspect_ratio=decrease"
    )
}

fn fit_dimensions(width: u32, height: u32, max_width: u32, max_height: u32) -> (u32, u32) {
    if width <= max_width && height <= max_height {
        return (width, height);
    }
    if u64::from(width) * u64::from(max_height) > u64::from(height) * u64::from(max_width) {
        let scaled_height = (u64::from(height) * u64::from(max_width) / u64::from(width))
            .max(1)
            .try_into()
            .unwrap_or(1);
        (max_width, scaled_height)
    } else {
        let scaled_width = (u64::from(width) * u64::from(max_height) / u64::from(height))
            .max(1)
            .try_into()
            .unwrap_or(1);
        (scaled_width, max_height)
    }
}

fn center_square_crop(image: &DynamicImage) -> CoreResult<DynamicImage> {
    let (width, height) = image.dimensions();
    let size = width.min(height);
    if size == 0 {
        return Err(CoreError::Payload(
            "profile picture image dimensions must be greater than zero".to_owned(),
        ));
    }
    let left = (width - size) / 2;
    let top = (height - size) / 2;
    Ok(image.crop_imm(left, top, size, size))
}

fn aspect_fit_jpeg(
    image: &DynamicImage,
    width: u32,
    height: u32,
    quality: u8,
    filter: FilterType,
) -> CoreResult<Bytes> {
    let resized = if image.width() == width && image.height() == height {
        image.clone()
    } else {
        image.resize(width, height, filter)
    };
    encode_jpeg_rgb(&resized.to_rgb8(), quality)
}

fn square_jpeg(image: &DynamicImage, size: u32, quality: u8) -> CoreResult<Bytes> {
    let resized = if image.width() == size && image.height() == size {
        image.clone()
    } else {
        image.resize_exact(size, size, FilterType::Lanczos3)
    };
    encode_jpeg_rgb(&resized.to_rgb8(), quality)
}

fn encode_jpeg_rgb(image: &RgbImage, quality: u8) -> CoreResult<Bytes> {
    let mut output = Vec::new();
    JpegEncoder::new_with_quality(&mut output, quality)
        .encode_image(image)
        .map_err(|error| CoreError::Payload(format!("JPEG encode failed: {error}")))?;
    Ok(Bytes::from(output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::Rgb;

    #[test]
    fn generates_aspect_fit_jpeg_thumbnail() {
        let source = sample_jpeg(200, 100);
        let thumbnail = generate_jpeg_thumbnail(&source, JpegThumbnailOptions::default()).unwrap();

        assert_eq!(thumbnail.source_width, 200);
        assert_eq!(thumbnail.source_height, 100);
        assert_eq!(thumbnail.width, DEFAULT_MESSAGE_THUMBNAIL_EDGE);
        assert_eq!(thumbnail.height, DEFAULT_MESSAGE_THUMBNAIL_EDGE / 2);
        assert!(thumbnail.jpeg.starts_with(&[0xff, 0xd8]));

        let decoded = decode_image(&thumbnail.jpeg, ImageProcessingLimits::default()).unwrap();
        assert_eq!(decoded.dimensions(), (32, 16));
    }

    #[test]
    fn keeps_small_thumbnail_dimensions_without_upscaling() {
        let source = sample_jpeg(20, 10);
        let thumbnail = generate_jpeg_thumbnail(&source, JpegThumbnailOptions::default()).unwrap();

        assert_eq!(thumbnail.width, 20);
        assert_eq!(thumbnail.height, 10);
        let decoded = decode_image(&thumbnail.jpeg, ImageProcessingLimits::default()).unwrap();
        assert_eq!(decoded.dimensions(), (20, 10));
    }

    #[test]
    fn generates_square_profile_picture_and_preview() {
        let source = sample_jpeg(80, 40);
        let profile = generate_profile_picture(
            &source,
            ProfilePictureOptions {
                image_size: 64,
                preview_size: 16,
                ..ProfilePictureOptions::default()
            },
        )
        .unwrap();

        assert_eq!(profile.source_width, 80);
        assert_eq!(profile.source_height, 40);
        assert_eq!(profile.image_size, 64);
        assert_eq!(profile.preview_size, 16);
        let image = decode_image(&profile.image, ImageProcessingLimits::default()).unwrap();
        let preview = decode_image(&profile.preview, ImageProcessingLimits::default()).unwrap();
        assert_eq!(image.dimensions(), (64, 64));
        assert_eq!(preview.dimensions(), (16, 16));
    }

    #[test]
    fn generates_link_preview_inline_and_high_quality_images() {
        let source = sample_jpeg(800, 400);
        let generated = generate_link_preview_images(
            &source,
            LinkPreviewImageOptions {
                high_quality_max_width: 160,
                high_quality_max_height: 160,
                ..LinkPreviewImageOptions::default()
            },
        )
        .unwrap();

        assert_eq!(generated.source_width, 800);
        assert_eq!(generated.source_height, 400);
        assert_eq!(generated.thumbnail_width, 32);
        assert_eq!(generated.thumbnail_height, 16);
        assert_eq!(generated.high_quality_width, 160);
        assert_eq!(generated.high_quality_height, 80);
        assert!(generated.jpeg_thumbnail.starts_with(&[0xff, 0xd8]));
        assert!(generated.high_quality_jpeg.starts_with(&[0xff, 0xd8]));

        let inline =
            decode_image(&generated.jpeg_thumbnail, ImageProcessingLimits::default()).unwrap();
        let high_quality = decode_image(
            &generated.high_quality_jpeg,
            ImageProcessingLimits::default(),
        )
        .unwrap();
        assert_eq!(inline.dimensions(), (32, 16));
        assert_eq!(high_quality.dimensions(), (160, 80));
    }

    #[test]
    fn rejects_empty_and_over_limit_input() {
        assert_eq!(
            generate_jpeg_thumbnail(&[], JpegThumbnailOptions::default())
                .unwrap_err()
                .to_string(),
            "payload error: image input must not be empty"
        );

        let source = sample_jpeg(4, 4);
        let err = generate_jpeg_thumbnail(
            &source,
            JpegThumbnailOptions {
                limits: ImageProcessingLimits {
                    max_input_bytes: source.len() - 1,
                    ..ImageProcessingLimits::default()
                },
                ..JpegThumbnailOptions::default()
            },
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "payload error: image input is {} bytes, exceeding limit {}",
                source.len(),
                source.len() - 1
            )
        );
    }

    #[test]
    fn rejects_invalid_output_options() {
        assert!(
            generate_jpeg_thumbnail(
                &sample_jpeg(4, 4),
                JpegThumbnailOptions {
                    max_width: 0,
                    ..JpegThumbnailOptions::default()
                },
            )
            .is_err()
        );
        assert!(
            generate_profile_picture(
                &sample_jpeg(4, 4),
                ProfilePictureOptions {
                    preview_size: 0,
                    ..ProfilePictureOptions::default()
                },
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn extracts_video_thumbnail_with_configured_ffmpeg_command() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = test_thumbnail_path("video-frame");
        std::fs::create_dir_all(&dir).unwrap();
        let frame_path = dir.join("frame.jpg");
        let log_path = dir.join("args.log");
        let ffmpeg_path = dir.join("fake-ffmpeg");
        let video_path = dir.join("clip.mp4");
        std::fs::write(&frame_path, sample_jpeg(96, 48)).unwrap();
        std::fs::write(&video_path, b"fake video").unwrap();
        std::fs::write(
            &ffmpeg_path,
            format!(
                "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$@\" > {}\nout=\"\"\nfor arg do out=\"$arg\"; done\ncp {} \"$out\"\n",
                shell_quote(&log_path),
                shell_quote(&frame_path),
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&ffmpeg_path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&ffmpeg_path, permissions).unwrap();

        let thumbnail = generate_video_thumbnail_from_file(
            &video_path,
            VideoThumbnailOptions {
                ffmpeg_path: ffmpeg_path.clone(),
                seek_time: "00:00:01".to_owned(),
                output: JpegThumbnailOptions {
                    max_width: 40,
                    max_height: 20,
                    ..JpegThumbnailOptions::default()
                },
                temp_dir: Some(dir.clone()),
            },
        )
        .unwrap();

        assert_eq!(thumbnail.source_width, 96);
        assert_eq!(thumbnail.source_height, 48);
        assert_eq!(thumbnail.width, 40);
        assert_eq!(thumbnail.height, 20);
        assert!(thumbnail.jpeg.starts_with(&[0xff, 0xd8]));
        let args = std::fs::read_to_string(&log_path).unwrap();
        let args = args.lines().collect::<Vec<_>>();
        assert_eq!(args.len(), 12);
        assert_eq!(
            &args[..11],
            &[
                "-ss",
                "00:00:01",
                "-i",
                &video_path.display().to_string(),
                "-y",
                "-vf",
                "scale=w=min(40\\,iw):h=min(20\\,ih):force_original_aspect_ratio=decrease",
                "-vframes",
                "1",
                "-f",
                "image2",
            ]
        );
        let output_path = Path::new(args[11]);
        assert_eq!(output_path.parent(), Some(dir.as_path()));
        let output_name = output_path.file_name().unwrap().to_string_lossy();
        assert!(output_name.starts_with("wa-core-video-thumbnail-"));
        assert!(output_name.ends_with(".jpg"));
    }

    #[cfg(unix)]
    #[test]
    fn extracts_pdf_thumbnail_with_configured_renderer_command() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = test_thumbnail_path("pdf-frame");
        std::fs::create_dir_all(&dir).unwrap();
        let frame_path = dir.join("page.jpg");
        let log_path = dir.join("args.log");
        let renderer_path = dir.join("fake-pdftoppm");
        let pdf_path = dir.join("doc.pdf");
        std::fs::write(&frame_path, sample_jpeg(120, 60)).unwrap();
        std::fs::write(&pdf_path, b"%PDF-1.7\n").unwrap();
        std::fs::write(
            &renderer_path,
            format!(
                "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$@\" > {}\nout=\"\"\nfor arg do out=\"$arg\"; done\ncp {} \"$out.jpg\"\n",
                shell_quote(&log_path),
                shell_quote(&frame_path),
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&renderer_path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&renderer_path, permissions).unwrap();

        let thumbnail = generate_pdf_thumbnail_from_file(
            &pdf_path,
            PdfThumbnailOptions {
                pdftoppm_path: renderer_path.clone(),
                page: 2,
                dpi: 96,
                output: JpegThumbnailOptions::default(),
                temp_dir: Some(dir.clone()),
            },
        )
        .unwrap();

        assert_eq!(thumbnail.source_width, 120);
        assert_eq!(thumbnail.source_height, 60);
        assert_eq!(thumbnail.width, 32);
        assert_eq!(thumbnail.height, 16);
        assert!(thumbnail.jpeg.starts_with(&[0xff, 0xd8]));
        let args = std::fs::read_to_string(&log_path).unwrap();
        let args = args.lines().collect::<Vec<_>>();
        assert_eq!(args.len(), 10);
        assert_eq!(
            &args[..9],
            &[
                "-f",
                "2",
                "-l",
                "2",
                "-singlefile",
                "-jpeg",
                "-r",
                "96",
                &pdf_path.display().to_string(),
            ]
        );
        let output_prefix = Path::new(args[9]);
        assert_eq!(output_prefix.parent(), Some(dir.as_path()));
        let output_name = output_prefix.file_name().unwrap().to_string_lossy();
        assert!(output_name.starts_with("wa-core-pdf-thumbnail-"));
        assert!(!output_name.ends_with(".jpg"));
    }

    fn sample_jpeg(width: u32, height: u32) -> Bytes {
        let image = RgbImage::from_fn(width, height, |x, y| {
            Rgb([(x % 255) as u8, (y % 255) as u8, ((x + y) % 255) as u8])
        });
        encode_jpeg_rgb(&image, 90).unwrap()
    }

    #[cfg(unix)]
    fn shell_quote(path: &Path) -> String {
        format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
    }

    #[cfg(unix)]
    fn test_thumbnail_path(label: &str) -> PathBuf {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("wa-core-thumbnail-{label}-{suffix}"))
    }
}
