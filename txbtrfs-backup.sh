#!/bin/bash

chmod 755 .git/subtree-cache/
git subtree split --prefix=fs/btrfs --annotate='(split) ' --rejoin --branch split || exit 1;
git push backup-di split2:master || exit 1;
chmod 000 .git/subtree-cache/
