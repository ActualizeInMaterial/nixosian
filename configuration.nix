# Edit this configuration file to define what should be installed on
# your system.  Help is available in the configuration.nix(5) man page
# and in the NixOS manual (accessible by running ‘nixos-help’).

#src: https://github.com/bjornfor/nixos-config/blob/master/configuration.nix

{ config, libs, pkgs, ... }:

let
vbox1 = "vbox1";
myz575 = "myzee";
myt400 = "myty";
hostname = vbox1; # select one from above

#  myDomain = "idno.name"; # src: https://github.com/bjornfor/nixos-config/blob/master/configuration.nix

#linux kernel version:
linuxPackages = pkgs.linuxPackages_4_5;

in  #from the above 'let'
{
  imports =
    [ # Include the results of the hardware scan.
    ./hardware-configuration.nix
    ];

#FIXME: is there a match?!
  fileSystems = if vbox1 == hostname then {
    "/vmsh" = {
      fsType = "vboxsf";
      device = "vmsharedfolder";
      options = [ "rw" ];
    }; #src: https://nixos.org/wiki/Installing_NixOS_in_a_VirtualBox_guest#Shared_Folders
  } else if myz575 == hostname then 
    throw "not set for myz575"
      else throw "Missing fileSystems settings for hostname \"${hostname}\"";

# List swap partitions activated at boot time.
#swapDevices = [
#  { device = "/dev/disk/by-label/swap"; }
#];

# Use the GRUB 2 boot loader.
      boot.loader.grub = {
#  boot.loader.grub.enable = true;
        enable = true;
#  boot.loader.grub.version = 2;
        version = 2;
# Define on which hard drive you want to install Grub.
#  boot.loader.grub.device = "/dev/sda";
        device = if vbox1 == hostname then
          "/dev/disk/by-id/ata-VBOX_HARDDISK_VB58dce9b3-6eca935a"
          else if myz575 == hostname then 
            throw "grub device for myz575 not yet set!"
              else "Missing boot.loader.grub.device setting for hostname \"${hostname}\"";
      };

      services.nixosManual.enable = true;


#FIXME: vim indenting for .nix
#  networking.hostName = hostname; #"nixosvm"; # Define your hostname.
#    networking.wireless.enable = false;  # Enables wireless support via wpa_supplicant.

      networking = {
        hostName = hostname;
        firewall.enable = true;
        firewall.allowPing = false; #ipv6 ping is always allowed, src: https://nixos.org/releases/nixos/unstable/nixos-16.09pre79453.32b7b00/manual/index.html#sec-firewall
          networkmanager.enable = false;
        enableWLAN = false;
        enableIPv6 = false;
        wireless.enable = false;
      };
# Select internationalisation properties.
      i18n = {
        consoleFont = "Lat2-Terminus16";
        consoleKeyMap = "us";
        defaultLocale = "en_US.UTF-8";
      };

# Set your time zone.
      time.timeZone = "Europe/Budapest";

# List packages installed in system profile. To search by name, run:
# $ nix-env -qaP | grep wget
      environment.systemPackages = with pkgs; [
        vim
          mc
          git
          wkhtmltopdf
# (callPackage ltsa {})
#    (asciidoc-full.override { enableExtraPlugins = true; })
#    anki  # flash card learning application
          apg
          arp-scan
          ascii
          aspell
          aspellDicts.en
#    aspellDicts.nb
#    attic
#    babeltrace
          bc
#    bind
#    bmon
#    bridge-utils
#    chromium #FIXME: enable
#    llvmPackages.clang   # for libclang, required by clang_complete.vim
#    clangAnalyzer  # a.k.a. scan-build
#    cmakeWithGui
          ctags
#    dash
#    ddrescue
#    dhex
          dia
          diffstat
          dmidecode
          dos2unix
#    dstat
#    eagle
          /*    (eclipses.eclipseWithPlugins {
                eclipse = eclipses.eclipse-cpp-45;
                jvmArgs = [ "-Xmx2048m" ];
                plugins = with eclipses.plugins;
                [ cdt gnuarmeclipse ];
                })*/
          elinks
#    evtest
          file
#    filezilla
#    firefoxWrapper
#    freecad
          gcc
          gdb
#    gitAndTools.qgit
#    gitFull
#    gnome3.dconf  # Required by virt-manager to store settings (dconf-service will be started when needed). NOTE: enabling GNOME 3 desktop auto-enables this.
#    gnumake
          gource
          gparted
#    gqrx
          graphviz
#    gsmartcontrol
          hdparm
          htop
          iftop
#    ioping
          iotop
          iptables
#    irssi
#    iw
#    kalibrate-rtl
#kde4.ark
#kde4.bluedevil
#kde4.gwenview
#kde4.kdemultimedia  # for volume control applet (kmix), and probably lots more
##kde4.networkmanagement
#kde4.okular
#    lftp
#    libfaketime
#    libreoffice
#    linssid
#    linuxPackages.perf
          lshw
          lsof
#    ltrace
#    lttng-tools
#    lynx
          manpages # for "man 2 fork" etc.
#    meld
#    mercurial
#    minicom
#    mosh
#    msmtp
#    mutt
#    ncdu
          networkmanager
#    networkmanagerapplet
#    nfs-utils
#    nixpkgs-lint
#    nix-generate-from-cpan
#    nix-prefetch-scripts
#    nix-repl
#    nmap_graphical
#    offlineimap
#    openconnect
#    openocd
#    openscad
#    p7zip
          parted
#    patchelf
          pavucontrol
#    pencil
          picocom
#    (pidgin-with-plugins.override { plugins = [ pidginsipe ]; })
#    poppler
#    posix_man_pages
          powertop
#    psmisc
#    pulseview  # sigrok GUI
#    pv
          pwgen
#    pythonFull
#    pythonPackages.demjson  # has a jsonlint command line tool (alternative: json_pp from perl)
#    pythonPackages.ipython
#    pythonPackages.sympy
#    python2nix
          qemu
#    qmmp
#qtcreator
#    remake
#    remmina
#    rmlint
#    rtl-sdr
#    saleae-logic
#    samba
          screen
#    sigrok-cli
#    silver-searcher
          simplescreenrecorder
          /*    (if hostname == myLaptop then
# My laptop (Asus UL30A) has upside down webcam. Flip it back.
let
libv4l_i686 = callPackage_i686 <nixpkgs/pkgs/os-specific/linux/v4l-utils> { qt5 = null; };
in
lib.overrideDerivation skype (attrs: {
installPhase = attrs.installPhase +
''
sed -i "2iexport LD_PRELOAD=${libv4l_i686}/lib/v4l1compat.so" "$out/bin/skype"
'';
})
else
# Other machines don't need the flip (use plain skype).
skype
)*/
#    sloccount
          smartmontools
#    socat
#    solfege
#    spice
#    spotify
#    sqlite-interactive
#    srecord
#    stdmanpages
#    subversion
#    surfraw
#    sweethome3d.application
taskwarrior  # causes grep help text to be printed each time a new terminal is started (bash completion script is buggy)
  tcpdump
#teamviewer  # changes hash all the time
#    telnet
#    tig
  traceroute
#    tree
#    unoconv
#    unrar #XXX: unfree license!
  unzip
#    vifm
#    vim_configurable
#    virtmanager
#    virtviewer
  vlc
#    weston
  wget
  wgetpaste
  which
#    wineUnstable
#    winpdb
  wireshark
#    wpa_supplicant
#    wpa_supplicant_gui
#    w3m
#    xchat
  youtube-dl

  ];

# List services that you want to enable:
#virtualisation.virtualbox.guest.enable = true; #already in hardware*nix

#Whether to run fsck on journaling filesystems such as ext3.
  boot.initrd.checkJournalingFS = false;
  boot.initrd.supportedFilesystems = [
    "btrfs"
  ];

  boot.kernel.sysctl = {

# TCP SYN Flood Protection
#src: https://www.ndchost.com/wiki/server-administration/hardening-tcpip-syn-flood
    "net.ipv4.tcp_syncookies" = 1;
    "net.ipv4.tcp_max_syn_backlog" = 2048;
    "net.ipv4.tcp_synack_retries" = 3;

# Disables packet forwarding
    "net.ipv4.ip_forward" = 0;
# Disables IP dynaddr
#net.ipv4.ip_dynaddr = 0
# Disable ECN
#net.ipv4.tcp_ecn = 0
# Enables source route verification
    "net.ipv4.conf.default.rp_filter" = 1;
# Enable reverse path
    "net.ipv4.conf.all.rp_filter" = 1;

# Enable SYN cookies (yum!)
# http://cr.yp.to/syncookies.html
#net.ipv4.tcp_syncookies = 1

# Disable source route
#net.ipv4.conf.all.accept_source_route = 0
#net.ipv4.conf.default.accept_source_route = 0

# Disable redirects
#net.ipv4.conf.all.accept_redirects = 0
#net.ipv4.conf.default.accept_redirects = 0

# Disable secure redirects
#net.ipv4.conf.all.secure_redirects = 0
#net.ipv4.conf.default.secure_redirects = 0

# Ignore ICMP broadcasts
#net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disables the magic-sysrq key
#kernel.sysrq = 0
# When the kernel panics, automatically reboot in 3 seconds
#kernel.panic = 3
# Allow for more PIDs (cool factor!); may break some programs
#kernel.pid_max = 999999

# You should compile nfsd into the kernel or add it
# to modules.autoload for this to work properly
# TCP Port for lock manager
#fs.nfs.nlm_tcpport = 0
# UDP Port for lock manager
#fs.nfs.nlm_udpport = 0
  };

# This fixes the touchpad resolution and 2-finger scroll on my Asus UL30A
# laptop (and it doesn't hurt my desktop settings)
#  boot.kernelModules = [ "psmouse" ];
#  boot.extraModprobeConfig = " options psmouse proto=imps ";
boot.blacklistedKernelModules = [
# This module is for debugging and generates gigantic amounts
# of log output, so it should never be loaded automatically.
  "evbug"
  "ideapad_laptop"
  "thinkpad_acpi"
  "nvram"
  "rfkill"
  "led_class"
#led_class               5565  1 rtsx_usb_sdmmc
#XXX: that is: led_class is used by rtsx_usb_sdmmc which is internal card reader of Z575 laptop
  "fglrx"
#blacklist radeon
#fglrx
#blacklist fb
#blacklist fbcon

# this is how you mute annoying beeps in console and shutdown
#blacklist pcspkr

#disable internal webcam                                                        
#[ 1230.363677] usb 2-3: new high-speed USB device number 5 using ehci-pci
#[ 1230.774015] uvcvideo: Found UVC 1.00 device Lenovo EasyCamera (5986:0364)
#[ 1230.792011] input: Lenovo EasyCamera as /devices/pci0000:00/0000:00:13.2/usb2
  "uvcvideo"
  "bluetooth"

  ];

  boot.kernelPackages = linuxPackages // {
  virtualbox = linuxPackages.virtualbox.override {
    enableExtensionPack = (myz575 == hostname);
  };
};
#boot.extraModulePackages = [ linuxPackages.lttng-modules ];  # fails on linux 3.18+

boot.consoleLogLevel = 9; #aka kernel cmdline: loglevel=9  (default 4)

#Whether to delete all files in /tmp during boot. TODO: find out if this happens before /tmp is mounted as tmpfs!
boot.cleanTmpDir = true;

boot.kernelParams = [
  "ipv6.disable=1"
  "pnp.debug=1"
#    "loglevel=9" #XXX: overriden by boot.consoleLogLevel
  "log_buf_len=10M"
  "printk.always_kmsg_dump=y"
  "printk.time=y"
  "mminit_loglevel=0"
  "memory_corruption_check=1"
  "nohz=on"
  "rcu_nocbs=1-3"
  "pcie_aspm=force"
  "fbcon=scrollback:4096k"
  "fbcon=font:ProFont6x11"
  "apic=debug"
  "dynamic_debug.verbose=1"
  "dyndbg=\"file arch/x86/kernel/apic/* +pflmt ; file drivers/video/* +pflmt ; file drivers/input/* -pflmt ; file drivers/acpi/* -pflmt\""
  "acpi_backlight=vendor"
  "radeon.audio=0"
  "radeon.lockup_timeout=999000"
  "radeon.test=0"
  "radeon.agpmode=-1"
  "radeon.benchmark=0"
  "radeon.tv=0"
  "radeon.hard_reset=1"
  "radeon.aspm=1"
  "radeon.msi=1"
  "radeon.pcie_gen2=-1"
  "radeon.no_wb=1"
  "radeon.dynclks=0"
  "radeon.r4xx_atom=0"
  "radeonfb"
  "radeon.fastfb=1"
  "radeon.dpm=1"
  "radeon.runpm=1"
  "rd.debug"
  "rd.udev.debug"
  "rd.memdebug=3"
  "net.ifnames=1"
  "slub_debug=U"
  "pax_sanitize_slab=full"
  "noefi"
#    "dolvm"
#    "dobtrfs"
  "console=tty1"
  "earlyprintk=vga"
  "CPUunderclocking"
  "radeon.modeset=1"
#console=tty1,ttyS0,115200n8 earlyprintk=vga,serial,ttyS0,115200,keep"
#radeon.modeset=1 allows X to start into gfx mode but consoles (vts) are also graphical (framebuffer like) from the start.

  ];


# Enable the OpenSSH daemon.
#      services.openssh.enable = true; #FIXME: conflicting definitions

# Enable CUPS to print documents.
  services.printing.enable = false;

  services.gpm.enable = false;
  services.sshd.enable = false;

#src: https://web.archive.org/web/20140704130237/https://nixos.org/repos/nix/configurations/trunk/misc/eelco/hobbit.nix
  fonts.enableGhostscriptFonts = false; #XXX: .exe ?
  fonts.enableCoreFonts = false; #XXX: this has the exe-s ?

# Enable the X11 windowing system.
#  services.xserver.enable = true;
#  services.xserver.layout = "us";
#  services.xserver.xkbOptions = "eurosign:e";

  services.xserver = 
  if myz575 == hostname then {
    synaptics.enable = true;
    synaptics.twoFingerScroll = true;
  } else {} // {
enable = true;
videoDrivers = [ "ati" "intel" "vesa" "modesetting" "virtualbox" ];
layout = "us, hu";
xkbModel = "pc105";
xkbOptions = "eurosign:e,terminate:ctrl_alt_bksp,numpad:microsoft,grp:alt_shift_toggle";
#xkbDisable = false; doesn't exist
#xkbVariant = ",";
xkbVariant = "basic,";
desktopManager.xfce.enable = true;
displayManager.auto = {
  enable = true;
  user = "z";
};
};
#services.xserver.displayManager.auto.enable = true;

# Enable the KDE Desktop Environment.
# services.xserver.displayManager.kdm.enable = true;
# services.xserver.desktopManager.kde4.enable = true;

# Define a user account. Don't forget to set a password with ‘passwd’.
# users.extraUsers.guest = {
#   isNormalUser = true;
#   uid = 1000;
# };

##### Users #####
users.extraUsers = {
  z = {
    description = "Full name";
    uid = 1000;
    extraGroups = [
#FIXME: see which are extraneous
      "adm"
        "audio"
        "cdrom"
#        "dialout"
#        "docker"
#        "libvirtd"
        "networkmanager"
        "plugdev"
        "systemd-journal"
        "tracing"
        "tty"
#        "usbtmc"
        "vboxusers"
        "video"
        "wheel"
        "wireshark"
    ];
    isNormalUser = true;
    initialPassword = "z";
# Subordinate user ids that user is allowed to use. They are set into
# /etc/subuid and are used by newuidmap for user namespaces. (Needed for
# LXC.) FIXME: what is LXC?
    subUidRanges = [
    { startUid = 100000; count = 65536; }
    ];
    subGidRanges = [
    { startGid = 100000; count = 65536; }
    ];

  };
};

users.extraGroups = {
  plugdev = { gid = 500; };
  tracing = { gid = 501; };
#    usbtmc = { gid = 502; };
  wireshark = { gid = 503; };
};

# The NixOS release to be compatible with for stateful data such as databases.
system.stateVersion = "16.09";

##### Misc stuff (shellInit, powerManagement etc.) #####
nix = {
  useChroot = true;
  gc.automatic = true;
  gc.dates = "03:15";#src: https://nixos.org/releases/nixos/14.12/nixos-14.12.374.61adf9e/manual/sec-nix-gc.html

# To not get caught by the '''"nix-collect-garbage -d" makes "nixos-rebuild
# switch" unusable when nixos.org is down"''' issue:
  extraOptions = ''
    gc-keep-outputs = true
    gc-keep-derivations = true
    build-cores = 0  # 0 means auto-detect number of CPUs (and use all)
    auto-optimise-store = true
    binary-caches-parallel-connections = 10
    '';
    #2nd src: https://github.com/avnik/nixos-configs/blob/master/common/nix.nix#L23
  #also see: http://anderspapitto.com/posts/2015-11-01-nixos-with-local-nixpkgs-checkout.html
  nixPath = [
    "nixpkgs=/etc/nixos/nixpkgs"
#      "nixos=/etc/nixpkgs/nixos" #dno what this is!
      "nixos-config=/etc/nixos/configuration.nix"
#      "private=/home/avn/nixos/private"
  ];
};


security.setuidOwners = [
{ # Limit access to dumpcap to root and members of the wireshark group.
  source = "${pkgs.wireshark}/bin/dumpcap";
  program = "dumpcap";
  owner = "root";
  group = "wireshark";
  setuid = true;
  setgid = false;
  permissions = "u+rx,g+x";
}
{ # Limit access to smartctl to root and members of the root group.
  source = "${pkgs.smartmontools}/bin/smartctl";
  program = "smartctl";
  owner = "root";
  group = "root";
  setuid = true;
  setgid = false;
  permissions = "u+rx,g+x";
}
];


security.sudo = {
  enable = true;
  wheelNeedsPassword = false;
};

#  security.pam.loginLimits = [
#XXX: no idea what this is doing:
#    { domain = "@audio"; type = "-"; item = "rtprio"; value = "75"; }
#    { domain = "@audio"; type = "-"; item = "memlock"; value = "500000"; }
#  ];

# Override similar to ~/.nixpkgs/config.nix (see "man configuration.nix" and
# search for "nixpkgs.config"). Also, make sure to read
# http://nixos.org/nixos/manual/#sec-customising-packages
nixpkgs.config = {
  allowUnfree = false;  # allow proprietary packages
    firefox.enableAdobeFlash = false;
  chromium.enablePepperFlash = false;
  packageOverrides = pkgs: {
#qtcreator = pkgs.qtcreator.override { qt48 = pkgs.qt48Full; };
#qemu = pkgs.qemu.override { spiceSupport = true; };
  };
};


hardware.pulseaudio.enable = true;
hardware.bluetooth.enable = false;
#      hardware.opengl.driSupport32Bit = true;
# KDE displays a warning if this isn't enabled
powerManagement.enable = true;

environment.shellAliases = {
  ".." = "cd ..";
  "..." = "cd ../..";
  "..2" = "cd ../..";
  "..3" = "cd ../../..";
  "..4" = "cd ../../../..";
};

/*environment.shellInit = lib.optionalString (hostname == myLaptop) ''
# "xset" makes my Asus UL30A touchpad move quite nicely.
test -n "$DISPLAY" && xset mouse 10/4 0
'';
 */

environment.interactiveShellInit = ''
# A nix query helper function
nq()
{
  case "$@" in
    -h|--help|"")
      printf "nq: A tiny nix-env wrapper to search for packages in package name, attribute name and description fields\n";
    printf "\nUsage: nq <case insensitive regexp>\n";
    return;;
    esac
      nix-env -qaP --description \* | grep -i "$@"
}
export HISTCONTROL=ignoreboth   # ignorespace + ignoredups
export HISTSIZE=1000000         # big big history
export HISTFILESIZE=$HISTSIZE
shopt -s histappend             # append to history, don't overwrite it
'';

/*environment.profileRelativeEnvVars = {
  GRC_BLOCKS_PATH = [ "/share/gnuradio/grc/blocks" ];
  PYTHONPATH = [ "/lib/python2.7/site-packages" ];
  };
 */

environment.sessionVariables = {
#FIXME: what does?
#    NIX_AUTO_INSTALL = "1";
};


#FIXME: this overwrites whatever was there before! need to append instead!(and only once) or just put the wanted result on github and url to it here
# Block advertisement domains (see
# http://winhelp2002.mvps.org/hosts.htm)
environment.etc."hosts".source =
pkgs.fetchurl {
  url = "http://winhelp2002.mvps.org/hosts.txt";
  sha256 = "1vxkv7dcp4mavcm8jqs1fkmizqf6d35kw276d0jl1rxag449caap";
};

# Make it easier to work with external scripts
/*  system.activationScripts.fhsCompat = ''
    fhscompat=0  # set to 1 or 0
    if [ "$fhscompat" = 1 ]; then
    echo "enabling (simple) FHS compatibility"
    mkdir -p /bin /usr/bin
    ln -sfv ${pkgs.bash}/bin/sh /bin/bash
    ln -sfv ${pkgs.perl}/bin/perl /usr/bin/perl
    ln -sfv ${pkgs.python27Full}/bin/python /usr/bin/python
    else
# clean up
find /bin /usr/bin -type l | while read file; do if [ "$file" != "/bin/sh" -a "$file" != "/usr/bin/env" ]; then rm -v "$file"; fi; done
fi
'';
 */

# Show git info in bash prompt and display a colorful hostname if using ssh.
programs.bash.promptInit = ''
export GIT_PS1_SHOWDIRTYSTATE=1
source ${pkgs.gitAndTools.gitFull}/share/git/contrib/completion/git-prompt.sh
__prompt_color="1;32m"
# Alternate color for hostname if the generated color clashes with prompt color
__alternate_color="1;33m"
__hostnamecolor="$__prompt_color"
# If logged in with ssh, pick a color derived from hostname
if [ -n "$SSH_CLIENT" ]; then
__hostnamecolor="1;$(${pkgs.nettools}/bin/hostname | od | tr ' ' '\n' | ${pkgs.gawk}/bin/awk '{total = total + $1}END{print 30 + (total % 6)}')m"
# Fixup color clash
if [ "$__hostnamecolor" = "$__prompt_color" ]; then
__hostnamecolor="$__alternate_color"
fi
fi
__red="1;31m"
PS1='\n$(ret=$?; test $ret -ne 0 && printf "\[\e[$__red\]$ret\[\e[0m\] ")\[\e[$__prompt_color\]\u@\[\e[$__hostnamecolor\]\h \[\e[$__prompt_color\]\w$(__git_ps1 " [git:%s]")\[\e[0m\]\n$ '
'';

programs.bash.enableCompletion = true;

virtualisation.virtualbox.host.enable = (hostname != vbox1);
virtualisation.virtualbox.host.enableHardening = true;


/*systemd.mounts = [
#{ mountConfig."tmp.mount" = {
#Options="mode=1777,strictatime,size=90%";
#};
#}
{
where = "/tmp";
#what = "tmpfs";
mountConfig = {
Options="mode=1777,strictatime,size=90%";
};
}

];
 */
 #the following is by/from: https://gist.github.com/sheenobu/09947df2480e693161d3b3d83daddd49
boot.tmpOnTmpfs = false;
#  boot.tmpOnTmpfs = true; #/tmp is on tmpfs ? yes! ok, not this time because overriden below!
systemd.mounts = [
{
  unitConfig = {
    DefaultDependencies = "no";
    Conflicts = [ "umount.target" ];
    Before = [ "local-fs.target" "umount.target" ];
    ConditionPathIsSymbolicLink = "!/tmp";
  };

  where = "/tmp";
  what = "tmpfs";
  mountConfig = {
    Type = "tmpfs";
    Options = "mode=1777,strictatime,size=90%";
  };
}
];

}
