# Translates a path in this process's mount namespace into the path of the same file as another
# process sees it, by matching the two processes' /proc/<pid>/mountinfo tables.
#
#   awk -v want=/data -f hostpath.awk /proc/self/mountinfo /proc/<pid>/mountinfo
#
# Home Assistant bind-mounts the app's folders (/data, /config, /homeassistant, ...) from the
# host. The other process is the host's init, and its table says where the same filesystem is
# mounted there: /mnt/data on Home Assistant OS, so /data is
# /mnt/data/supervisor/addons/data/<slug> as the host sees it.
#
# Prints the host path. Prints nothing and exits 1 if the other table has no mount of the filesystem
# that holds the path. Uses only POSIX awk, so it runs under mawk, the awk of the Debian base image.
#
# mountinfo fields: 1 id, 2 parent id, 3 major:minor, 4 root of the mount inside its filesystem,
# 5 mount point, 6 options, then optional fields up to a "-", then fstype, source, super options.
# Spaces and a few other characters in paths are written as \ooo octal escapes.

function unescape(text,    out, i, chunk) {
    out = ""
    i = 1
    while (i <= length(text)) {
        chunk = substr(text, i, 4)
        if (chunk ~ /^\\[0-7][0-7][0-7]$/) {
            out = out sprintf("%c", substr(chunk, 2, 1) * 64 + substr(chunk, 3, 1) * 8 + substr(chunk, 4, 1))
            i += 4
        } else {
            out = out substr(text, i, 1)
            i += 1
        }
    }
    return out
}

# Is path equal to, or inside, base?
function inside(path, base) {
    return base == "/" || path == base || index(path, base "/") == 1
}

# First table: this process. The deepest mount point that contains the wanted path says which
# filesystem it is on, and where in that filesystem.
NR == FNR {
    mount_point = unescape($5)
    if (inside(want, mount_point) && length(mount_point) >= best_mount) {
        best_mount = length(mount_point)
        device = $3
        root = unescape($4)
        rest = (mount_point == "/") ? want : substr(want, length(mount_point) + 1)
    }
    next
}

# Second table: the other process. Among its mounts of the same filesystem, the one whose root is
# the deepest ancestor of the file is the most specific, and gives the path.
{
    if ($3 == device && device != "") {
        other_root = unescape($4)
        in_filesystem = (root == "/") ? rest : root rest
        if (inside(in_filesystem, other_root) && length(other_root) >= best_root) {
            best_root = length(other_root)
            other_mount = unescape($5)
            tail = (other_root == "/") ? in_filesystem : substr(in_filesystem, length(other_root) + 1)
        }
    }
}

END {
    if (other_mount == "") {
        exit 1
    }
    print (other_mount == "/") ? tail : other_mount tail
}
