import argparse
import numpy as np
from scipy.io import wavfile

# ---- DTMF setup ----
DTMF = {
    '1': (697, 1209), '2': (697, 1336), '3': (697, 1477), 'A': (697, 1633),
    '4': (770, 1209), '5': (770, 1336), '6': (770, 1477), 'B': (770, 1633),
    '7': (852, 1209), '8': (852, 1336), '9': (852, 1477), 'C': (852, 1633),
    '*': (941, 1209), '0': (941, 1336), '#': (941, 1477), 'D': (941, 1633),
}
LOW_FREQS  = np.array([697, 770, 852, 941], dtype=float)
HIGH_FREQS = np.array([1209, 1336, 1477, 1633], dtype=float)

# reverse map from (low, high) -> digit
PAIR2KEY = {v: k for k, v in DTMF.items()}

def goertzel_power(x, fs, f):
    """Compute Goertzel power for a single frequency f on signal x."""
    n = len(x)
    k = int(round(n * f / fs))
    w = 2.0 * np.pi * k / n
    coeff = 2.0 * np.cos(w)
    s0 = s1 = s2 = 0.0
    for sample in x:
        s0 = sample + coeff * s1 - s2
        s2, s1 = s1, s0
    return s1*s1 + s2*s2 - coeff*s1*s2

def segment_tones(sig, fs, min_tone_s=0.04):
    """
    Segment signal into tone regions using smoothed envelope thresholding.
    Returns list of (start_idx, end_idx) for each tone.
    """
    # mono, float, normalized
    if sig.ndim == 2:
        sig = sig.mean(axis=1)
    sig = sig.astype(np.float64)
    if sig.dtype != np.float64:
        sig = sig.astype(np.float64)
    if sig.max() != 0:
        sig = sig / max(1.0, np.max(np.abs(sig)))

    # smooth envelope (~10 ms window)
    win = max(1, int(0.010 * fs))
    env = np.convolve(np.abs(sig), np.ones(win)/win, mode="same")
    thr = 0.25 * env.max()  # conservative threshold
    active = env > thr

    # find contiguous active regions
    idx = np.flatnonzero(active)
    if len(idx) == 0:
        return []

    # split by gaps
    gaps = np.where(np.diff(idx) > 1)[0]
    starts = np.r_[idx[0], idx[gaps+1]]
    ends   = np.r_[idx[gaps], idx[-1]]

    # keep segments long enough to be a tone
    min_len = int(min_tone_s * fs)
    segments = [(int(s), int(e)+1) for s, e in zip(starts, ends) if (e - s + 1) >= min_len]
    return segments

def decode_segment(x, fs):
    """Decode one tone segment into a single DTMF key."""
    # take center portion to avoid boundary/silence bleed
    n = len(x)
    if n <= 0:
        return None
    slice_len = int(min(n, 0.06 * fs))  # ~60 ms center
    start = (n - slice_len) // 2
    seg = x[start:start+slice_len].astype(np.float64)

    # apply a Hamming window to reduce leakage
    seg = seg * np.hamming(len(seg))

    # compute Goertzel power for all candidate freqs
    low_powers  = [goertzel_power(seg, fs, f) for f in LOW_FREQS]
    high_powers = [goertzel_power(seg, fs, f) for f in HIGH_FREQS]
    low_idx  = int(np.argmax(low_powers))
    high_idx = int(np.argmax(high_powers))
    low_f  = int(LOW_FREQS[low_idx])
    high_f = int(HIGH_FREQS[high_idx])

    return PAIR2KEY.get((low_f, high_f))

def decode_wav_digits(path):
    fs, data = wavfile.read(path)
    # normalize to float in [-1,1]
    if data.dtype == np.int16:
        sig = data.astype(np.float64) / 32768.0
    elif data.dtype == np.int32:
        sig = data.astype(np.float64) / 2147483648.0
    else:
        sig = data.astype(np.float64)
        if np.max(np.abs(sig)) > 1e-9:
            sig = sig / np.max(np.abs(sig))

    segments = segment_tones(sig, fs)
    digits = []
    for s, e in segments:
        key = decode_segment(sig[s:e], fs)
        if key is not None:
            digits.append(key)
    return ''.join(digits)

def invmod(a, m):
    # Python 3.8+: pow(a, -1, m) works; keep a fallback
    try:
        return pow(a, -1, m)
    except TypeError:
        # extended Euclid
        t, newt = 0, 1
        r, newr = m, a
        while newr != 0:
            q = r // newr
            t, newt = newt, t - q * newt
            r, newr = newr, r - q * newr
        if r > 1: raise ValueError("a not invertible")
        if t < 0: t += m
        return t

def long_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, 'big')

def main():


    p_str = decode_wav_digits('p_dial.wav')
    q_str = decode_wav_digits('q_dial.wav')
    c_str = decode_wav_digits('message.wav')

    if not (p_str and q_str and c_str):
        raise SystemExit("Failed to decode one or more WAV files. Check audio levels/paths.")

    print(f"[+] Decoded p: {p_str[:10]}... ({len(p_str)} digits)")
    print(f"[+] Decoded q: {q_str[:10]}... ({len(q_str)} digits)")
    print(f"[+] Decoded c: {c_str[:10]}... ({len(c_str)} digits)")

    p = int(p_str)
    q = int(q_str)
    c = int(c_str)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = invmod(e, phi)

    m = pow(c, d, n)
    pt = long_to_bytes(m)

    try:
        decoded = pt.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        decoded = pt.decode("latin-1", errors="replace")

    print(f"\n[+] Plaintext bytes: {pt!r}")
    print(f"[+] Plaintext (decoded): {decoded}")

if __name__ == "__main__":
    main()
