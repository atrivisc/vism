#!/usr/bin/env bash

if [ "$(id -u)" -eq 0 ]; then
    echo "This script must not be run as root!"
    exit 1
fi

### Config ###
jail_dir=${JAIL_DIR:-/tmp/jail}
selinux_enabled=${SELINUX_ENABLED:-1}

### Selinux setup ###
selinux_setup() {
  selinux_enforcing=$(getenforce)

  if [[ $? -ne 0 ]]; then
      echo "Selinux is not installed"
      exit 1
  fi

  if [[ "$selinux_enforcing" != "Enforcing" ]]; then
      echo "Selinux is not enforcing"
      exit 1
  fi

  cat <<EOF > /tmp/restrict_script.te
module restrict_script 1.0;

require {
    type unconfined_t;
    class file { write execute create append };
    class process { execmem };
    attribute file_type, non_auth_file_type, non_security_file_type;
}

type restrict_script_t;
typeattribute restrict_script_t file_type, non_auth_file_type, non_security_file_type;;

dontaudit restrict_script_t self:file { write execute create append };

#dontaudit restrict_script_t self:process { execmem };
EOF
  checkmodule -M -m -o /tmp/restrict_script.mod /tmp/restrict_script.te
  semodule_package -o /tmp/restrict_script.pp -m /tmp/restrict_script.mod
  sudo semodule -i /tmp/restrict_script.pp

}

if [[ "$selinux_enabled" -eq "1" ]]; then
  selinux_setup;
fi

### Jail setup ###
openssl_version=$(openssl version 2>/dev/null)

if [[ $? -ne 0 ]]; then
    echo "OpenSSL is not installed."
    exit 1
fi

if ! [[ "$openssl_version" =~ ^OpenSSL\ 3 ]]; then
    echo "OpenSSL 3.x is not installed. Current version: $openssl_version"
    exit 1
fi

mkdir -p "$jail_dir/tmp"

copy_to_env() {
    local path="$1"
    local dir=$(dirname "${path:1}")
    mkdir -p "$jail_dir/$dir"
    cp "$path" "$jail_dir/$dir"
}

openssl_path=$(which openssl)
copy_to_env $openssl_path

ldd "$openssl_path" | grep -oP '\s/([^\s])*' | while read -r lib_path; do
  copy_to_env $lib_path
done

_=$(unshare -muinpUCT -r chroot $jail_dir $openssl_path version)

if [[ $? -ne 0 ]]; then
    echo "Failed to set up chroot environment."
    exit 1
fi
