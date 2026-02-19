"""
Tier 7 — STEGANOGRAPHY: LSB Text-in-Image
==========================================
Hide the existence of the message itself.

LSB (Least Significant Bit) steganography encodes text into the
least significant bits of image pixel values. The visual change is
imperceptible to the human eye — a pixel with value 200 becomes 201.
The image looks identical. The message is invisible.

This is the difference between encryption (hides the content) and
steganography (hides the fact that a message exists at all).

Combined with the encryption tiers above:
  Encrypt your message (no one can read it) →
  Steganography (no one knows it's there)

Carrier format: PNG or any lossless image (JPEG will destroy LSB data)
Encoding:       UTF-8 text → bits → LSB of R channel, row by row
Terminator:     16 zero bits marks end of message

Capacity:       (width × height) // 8  bytes maximum

Dependencies: Pillow >= 10.0
"""

from PIL import Image
import io
from typing import Union


class LSBSteganography:
    """Hide and extract text messages in image pixel LSBs."""

    TERMINATOR_BITS = 16   # 16 zero bits = end of message marker

    def hide(self, image_input: Union[str, bytes, Image.Image],
             message: str) -> bytes:
        """
        Embed message into image using LSB of the red channel.

        Args:
            image_input : file path, raw image bytes, or PIL Image
            message     : UTF-8 text to hide

        Returns:
            PNG bytes of the stego image (visually identical to input)
        """
        img = self._load(image_input).convert("RGB")
        pixels = list(img.getdata())

        bits = self._text_to_bits(message) + [0] * self.TERMINATOR_BITS
        capacity = len(pixels)

        if len(bits) > capacity:
            raise ValueError(
                f"Message too long: {len(bits)} bits needed, "
                f"{capacity} pixels available ({capacity // 8} bytes max)."
            )

        new_pixels = []
        for i, px in enumerate(pixels):
            if i < len(bits):
                r, g, b = px
                r = (r & 0xFE) | bits[i]   # replace LSB of red channel
                new_pixels.append((r, g, b))
            else:
                new_pixels.append(px)

        out = Image.new("RGB", img.size)
        out.putdata(new_pixels)

        buf = io.BytesIO()
        out.save(buf, format="PNG")
        return buf.getvalue()

    def extract(self, image_input: Union[str, bytes, Image.Image]) -> str:
        """
        Extract hidden message from a stego image.

        Returns:
            The hidden UTF-8 string, or empty string if none found.
        """
        img = self._load(image_input).convert("RGB")
        pixels = list(img.getdata())

        bits = [(px[0] & 1) for px in pixels]   # LSB of red channel

        # Collect bits until 16 consecutive zeros (terminator)
        message_bits = []
        zero_run = 0
        for bit in bits:
            if bit == 0:
                zero_run += 1
            else:
                zero_run = 0
            message_bits.append(bit)
            if zero_run >= self.TERMINATOR_BITS:
                message_bits = message_bits[:-self.TERMINATOR_BITS]
                break

        return self._bits_to_text(message_bits)

    # ── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _load(src: Union[str, bytes, Image.Image]) -> Image.Image:
        if isinstance(src, Image.Image):
            return src
        if isinstance(src, (bytes, bytearray)):
            return Image.open(io.BytesIO(src))
        return Image.open(src)

    @staticmethod
    def _text_to_bits(text: str) -> list:
        bits = []
        for byte in text.encode("utf-8"):
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

    @staticmethod
    def _bits_to_text(bits: list) -> str:
        chars = []
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            if byte:
                chars.append(chr(byte))
        try:
            return "".join(chars).encode("latin-1").decode("utf-8", errors="ignore")
        except Exception:
            return "".join(chars)

    @staticmethod
    def max_capacity_bytes(image_input: Union[str, bytes, Image.Image]) -> int:
        """Return maximum message bytes this image can carry."""
        if isinstance(image_input, Image.Image):
            img = image_input
        elif isinstance(image_input, (bytes, bytearray)):
            img = Image.open(io.BytesIO(image_input))
        else:
            img = Image.open(image_input)
        w, h = img.size
        return (w * h) // 8
