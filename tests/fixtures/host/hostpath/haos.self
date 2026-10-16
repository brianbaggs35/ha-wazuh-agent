1000 999 0:50 / / rw,relatime - overlay overlay rw,lowerdir=/mnt/data/docker/overlay2/l/AAA,upperdir=/mnt/data/docker/overlay2/x/diff,workdir=/mnt/data/docker/overlay2/x/work
1001 1000 0:51 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
1010 1000 259:8 /supervisor/addons/data/local_wazuh_agent /data rw,relatime - ext4 /dev/disk/by-label/hassos-data rw,commit=30
1011 1000 259:8 /supervisor/homeassistant /homeassistant ro,relatime - ext4 /dev/disk/by-label/hassos-data rw,commit=30
1012 1000 259:8 /supervisor/ssl /ssl ro,relatime - ext4 /dev/disk/by-label/hassos-data rw,commit=30
1013 1000 259:8 /supervisor/addon_configs/local_wazuh_agent /config ro,relatime - ext4 /dev/disk/by-label/hassos-data rw,commit=30
1014 1000 259:8 /logs /var/log/journal ro,relatime - ext4 /dev/disk/by-label/hassos-data rw,commit=30
