# <img align="right" src="/Web/static/img/logo_shadow.png" alt="openvk" title="openvk" width="15%">OpenVK
# <img align="right" src="/Web/static/img/logo_shadow.png" alt="openvk" title="openvk" width="15%">OpenVK
This repo contains modified [OpenVK](https://github.com/openvk/openvk) version that uses VKAPI instead of local db.

To enable it, set option in `openvk.yml` - `openvk.vk.enabled` = true.

If you want to disable it, don't forget to clear cache in that dir: `chandler/tmp/cache/di_openvk`

It is not recommended to install this on a production server!
