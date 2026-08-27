# ssh

Installs and starts the SSH server. Optional daemon drop-ins are variable-driven
and should be conservative to avoid lockouts. The drop-in directory remains
private to root, matching Rocky's packaged `0700` mode.
