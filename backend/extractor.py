from io import BytesIO
from typing import List
from urllib.parse import urlparse

from PIL import Image
from pdf2image import convert_from_bytes
from pyzbar.pyzbar import decode


def _urls_from_image(image: Image.Image) -> List[str]:
    """Decode URL payloads from a PIL image."""
    urls = []
    for code in decode(image):
        try:
            value = code.data.decode("utf-8").strip()
        except (AttributeError, UnicodeDecodeError):
            continue

        parsed = urlparse(value)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            urls.append(value)
    return urls


def extract_qr_from_bytes(file_bytes: bytes, filename: str) -> List[str]:
    """Return unique HTTP(S) URLs decoded from a PDF, PNG, or JPG.

    Errors from unsupported, malformed, or unreadable files are printed and
    result in an empty (or partial, for multi-page PDFs) list.
    """
    urls = []
    try:
        if filename.lower().endswith(".pdf"):
            for page in convert_from_bytes(file_bytes):
                try:
                    urls.extend(_urls_from_image(page))
                except Exception as exc:
                    print(f"Error decoding QR code from PDF page: {exc}")
        elif filename.lower().endswith((".png", ".jpg", ".jpeg")):
            with Image.open(BytesIO(file_bytes)) as image:
                urls.extend(_urls_from_image(image))
        else:
            print(f"Unsupported file type: {filename}")
    except Exception as exc:
        print(f"Error extracting QR codes from {filename}: {exc}")

    # Preserve discovery order while removing duplicates.
    return list(dict.fromkeys(urls))
