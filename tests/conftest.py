import os

# Qt needs a platform plugin even for widget construction. Offscreen lets the
# whole UI layer be exercised in CI with no display.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
