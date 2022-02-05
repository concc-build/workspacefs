# workspacefs

> A FUSE-based network filesystem for distributed build systems

The main purpose of workspacefs is sharing a project workspace with containers
in the concc distributed build system.  However, this may be useful for other
systems which need sharing files with remote entities.

Currently, workspacefs supports only the SFTP protocol.  Other protocols may be
supported in the future.

## Configuration

Put a single YAML file called `workspacefs.yaml` in a mount point directory.

```yaml
fuse:
  mount-options:
    - fsname=workspacefs
    - default_permissions
  fusermount: /usr/bin/fusermount3
  time-gran: 1000000000

uid-map:
  - local: 0
    remote: 1000

gid-map:
  - local: 0
    remote: 1000

cache:
  excludes:
    - glob/patterns
  page-cache:
    excludes:
      - glob/patterns
  dentry-cache:
    excludes:
      - glob/patterns
  attr:
    timeout: 1d
    excludes:
      - glob/patterns
  entry:
    timeout: 1d
    excludes:
      - glob/patterns
  negative:
    timeout: 1d
    excludes:
      - glob/patterns

remote:
  sftp:
    user: concc
    host: hostname
    port: 2222
    path: /workspace
    ssh-command: sshpass -f /tmp/password ssh
```

`workspacefs.yaml` will not be accessible once the target filesystem is mounted
onto the mount point.

## Inspecting workspacefs

workspacefs provides special files which make users possible to inspect internal
states of workspacefs easily.  These files are found in the `.workspacefs.d`
directory placed in the mount point directory.

Currently, there is no file in this directory.  We plan to add files which
contain the following information:

* Entries in caches
* Statistics
* Log messages

## Acknowledgments

workspacefs was started as a fork of [ubnt-intrepid/sshfs-rs].

workspacefs is implemented using [masnagam/polyfuse] which is a fork of
[ubnt-intrepid/polyfuse].

## License

Licensed under either of

* Apache License, Version 2.0
  ([LICENSE-APACHE] or http://www.apache.org/licenses/LICENSE-2.0)
* MIT License
  ([LICENSE-MIT] or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.

[ubnt-intrepid/sshfs-rs]: https://github.com/ubnt-intrepid/sshfs-rs
[masnagam/polyfuse]: https://github.com/masnagam/polyfuse
[ubnt-intrepid/polyfuse]: https://github.com/ubnt-intrepid/polyfuse
[LICENSE-APACHE]: ./LICENSE-APACHE
[LICENSE-MIT]: ./LICENSE-MIT
