"""Shared base for the two pages built out of level selectors.

Protection and Hardening are the same page with different families on it, so the
status plumbing, the apply path and the banner handling live here once.

The rule this base exists to enforce, inherited from the Fedora app: a selector
is only ever moved by `set_active_level`, driven by what the broker reports. It
is never moved because a click succeeded, and never moved optimistically. On
Windows that matters more than it did on Linux, because more changes here can be
refused after being accepted -- Tamper Protection, a domain policy, a licence
tier -- and a control that moved on click would claim protection the machine
does not have.
"""

from PySide6.QtWidgets import QLabel

from ..backend.errors import ChangeBlocked, GuardRefused
from ..data.levels import get_family
from ..widgets.level_selector import LevelSelector
from ..widgets.page import Banner, Group, Page


class LevelFamilyPage(Page):
    #: Subclasses set these.
    FAMILIES = ()
    TITLE = ""
    SUBTITLE = ""

    def __init__(self, window, parent=None):
        super().__init__(self.TITLE, self.SUBTITLE, parent)
        self.window = window
        self.broker = window.broker
        self.powershell = window.powershell
        self.settings = window.settings

        self.banner = Banner(parent=self)
        self.banner.hide_message()
        self.add(self.banner)

        self.selectors = {}
        self._build_families()
        self.build_extras()
        self.add_stretch()

        self._loaded = False

    # -- construction ---------------------------------------------------------

    def _build_families(self):
        for family_id in self.FAMILIES:
            family = get_family(family_id)
            if family is None:
                continue
            group = Group(family.title, family.subtitle, self)
            selector = LevelSelector(
                family.levels,
                self._make_apply_handler(family_id),
                self.window,
                confirm_heading=family.title,
                parent=group,
            )
            self.selectors[family_id] = selector
            group.add(selector)

            if family.footnote:
                note = QLabel(family.footnote, group)
                note.setObjectName("rowDetail")
                note.setWordWrap(True)
                group.add(note)

            self.add(group)

    def build_extras(self):
        """Subclass hook for anything beyond the level selectors."""

    # -- applying -------------------------------------------------------------

    def _make_apply_handler(self, family_id):
        def handler(level, done):
            def on_result(result, error):
                if error is None:
                    self._on_applied(family_id, level, result or {})
                    done(not (result or {}).get('restoreFailures'))
                    return
                self._on_apply_error(family_id, level, error)
                # done(False) leaves the selector where the system is. The
                # failure is explained in the banner rather than by moving a
                # control to a state that was not reached.
                done(False)

            self.broker.apply_level(family_id, level.id, on_result)

        return handler

    def _on_applied(self, family_id, level, result):
        notes = result.get("notes") or {}
        messages = []
        if notes.get("rebootRequired"):
            messages.append(
                "A restart is needed before this takes effect. Until then the setting is "
                "recorded but not in force.")
        elif notes.get("rebootRecommended") or notes.get("restartApplicationsRequired"):
            messages.append(
                "Programs pick this up the next time they start. Restart anything important, "
                "or reboot when convenient.")
        if result.get("restoreFailures"):
            failed = ", ".join(f["entry"] for f in result["restoreFailures"])
            messages.append(f"Some settings could not be put back and are still applied: {failed}")

        family = get_family(family_id)
        title = (f"{family.title}: restoration incomplete" if result.get("restoreFailures")
                 else f"{family.title} is now {level.label}")
        self.banner.show_message(
            title, "\n\n".join(messages) if messages else "The change is in force now.",
            tone="warning" if messages else "ok")
        self.refresh()

    def _on_apply_error(self, family_id, level, error):
        family = get_family(family_id)
        if isinstance(error, GuardRefused):
            # Not a failure: the app protecting the user from a setting. Said
            # differently, and with a different colour, because it is different.
            self.banner.show_message(
                f"{family.title} — {level.label} was not applied", str(error), tone="warning")
            return
        if isinstance(error, ChangeBlocked):
            self.banner.show_message(
                "Windows refused this change", str(error), tone="error")
            return
        self.banner.show_message(
            f"{family.title} could not be set to {level.label}", str(error), tone="error")

    # -- reading state --------------------------------------------------------

    def refresh(self):
        def on_status(result, error):
            if error is not None:
                self.on_status_error(error)
                return
            self._loaded = True
            recorded = ((result or {}).get("recorded") or {}).get("families") or {}
            for family_id, selector in self.selectors.items():
                level = (recorded.get(family_id) or {}).get("level", "off")
                selector.setEnabled(True)
                selector.set_active_level(level)
            incomplete = [family_id for family_id in self.selectors
                          if (recorded.get(family_id) or {}).get('incomplete')]
            if incomplete:
                self.banner.show_message('A previous change is incomplete',
                    'The displayed levels are the last completed choices. Some settings may have changed. '
                    'Choose Off to restore the saved originals for: ' + ', '.join(incomplete), tone='warning')
            self.on_status(result or {})

        self.broker.status(on_status)

    def on_status(self, status):
        """Subclass hook, called with the full status payload."""

    def on_status_error(self, error):
        for selector in self.selectors.values():
            selector.setEnabled(False)
        self.banner.show_message(
            "Current settings could not be read",
            f"{error}\n\nThe controls are disabled because current settings could not be verified.",
            tone="error",
        )
