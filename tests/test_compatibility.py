from aurascan.core.compatibility import (
    detect_desktop_session,
    detect_package_manager_capabilities,
    distro_from_os_release,
    parse_os_release,
)


def test_distro_detection_support_tiers():
    cases = [
        ('ID=arch\nNAME="Arch Linux"\n', "arch", "supported"),
        ('ID=endeavouros\nID_LIKE=arch\nNAME="EndeavourOS"\n', "endeavouros", "supported"),
        ('ID=cachyos\nID_LIKE=arch\nNAME="CachyOS"\n', "cachyos", "supported"),
        ('ID=manjaro\nID_LIKE=arch\nNAME="Manjaro Linux"\n', "manjaro", "supported_with_caveats"),
        ('ID=stormos\nID_LIKE="arch linux"\nNAME="StormOS"\n', "stormos", "best_effort"),
    ]

    for text, distro_id, tier in cases:
        info = distro_from_os_release(parse_os_release(text))
        assert info.distro_id == distro_id
        assert info.support_tier == tier
        assert info.arch_family is True


def test_non_arch_distro_is_unsupported():
    info = distro_from_os_release(parse_os_release("ID=fedora\nNAME=Fedora\n"))

    assert info.support_tier == "unsupported"
    assert info.arch_family is False


def test_package_manager_capabilities_report_found_and_missing_tools():
    caps = detect_package_manager_capabilities(lambda name: f"/usr/bin/{name}" if name in {"pacman", "yay"} else None)
    data = caps.to_dict()

    assert caps.found("pacman") is True
    assert "yay" in data["found"]
    assert "paru" in data["missing"]


def test_desktop_session_detection_common_desktops():
    kde = detect_desktop_session({"XDG_SESSION_TYPE": "wayland", "XDG_CURRENT_DESKTOP": "KDE"})
    gnome = detect_desktop_session({"XDG_SESSION_TYPE": "wayland", "XDG_CURRENT_DESKTOP": "GNOME"})
    xfce = detect_desktop_session({"XDG_SESSION_TYPE": "x11", "XDG_CURRENT_DESKTOP": "XFCE"})
    tiling = detect_desktop_session({"XDG_SESSION_TYPE": "wayland", "DESKTOP_SESSION": "sway"})

    assert kde.primary_desktop == "kde"
    assert kde.tray_support == "best"
    assert gnome.primary_desktop == "gnome"
    assert gnome.tray_support == "extension_required"
    assert xfce.primary_desktop == "xfce"
    assert xfce.tray_support == "expected"
    assert tiling.primary_desktop == "tiling"
    assert tiling.tray_support == "manual_tray_host"
