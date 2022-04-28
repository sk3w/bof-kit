use colored::Colorize;
use itertools::Itertools;
use goblin::error::Result;
use goblin::pe::{Coff, symbol::Symbol};

/// Image file machine constants (winnt.h)
/// https://docs.microsoft.com/en-us/windows/win32/sysinfo/image-file-machine-constants
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

/// Exported entrypoint for CS Beacon BOFs
/// https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm
const BEACON_ENTRYPOINT: &'static str = "go";

/// Exported functions supplied by Beacon (Cobalt Strike 4.1)
/// https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/beacon.h
static BEACON_EXPORTS: &[&str] = &[
    // data API
    "BeaconDataParse",
    "BeaconDataInt",
    "BeaconDataShort",
    "BeaconDataLength",
    "BeaconDataExtract",
    // format API
    "BeaconFormatAlloc",
    "BeaconFormatReset",
    "BeaconFormatFree",
    "BeaconFormatAppend",
    "BeaconFormatPrintf",
    "BeaconFormatToString",
    "BeaconFormatInt",
    // Output Functions
    "BeaconPrintf",
    "BeaconOutput",
    // Token Functions
    "BeaconUseToken",
    "BeaconRevertToken",
    "BeaconIsAdmin",
    // Spawn+Inject Functions
    "BeaconGetSpawnTo",
    "BeaconInjectProcess",
    "BeaconInjectTemporaryProcess",
    "BeaconCleanupProcess",
    // Utility Functions
    "toWideChar",
];

/// Win32 functions built into Beacon
/// https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm
static WIN32_BUILTIN: &[&str] = &[
    "GetProcAddress",
    "LoadLibraryA",
    "GetModuleHandle",
    "FreeLibrary",
];

/// Common Win32 libraries
static WIN32_MODULES: &[&str] = &[
    "NTDLL",
    "KERNEL32",
    "KERNELBASE",
    "GDI32",
    "USER32",
    "COMCTL32",
    "COMDLG32",
    "WS2_32",
    "ADVAPI32",
    "NETAPI32",
    "OLE32",
    "MSVCRT",
    "BASESRV",
    "CSRSRV",
    "WINSRV",
    "WININET",
];

pub struct Bof<'a>(Coff<'a>);

impl<'a> Bof<'a> {
    pub fn parse(buffer: &'a [u8]) -> Result<Self> {
        Coff::parse(buffer).map(|coff| Self(coff))
    }

    pub fn imports(&self) -> impl Iterator<Item=Symbol> + '_ {
        self.0.symbols.iter()
            .map(|tuple| { tuple.2 })
            .filter(move |s| {
                s.name(&self.0.strings).unwrap().starts_with(self.import_prefix())
            })
    }

    fn import_prefix(&self) -> &str {
        match self.0.header.machine {
            IMAGE_FILE_MACHINE_I386 => "__imp__",
            IMAGE_FILE_MACHINE_AMD64 => "__imp_",
            _ => panic!("Unsupported machine type")
        }
    }
}

pub fn parse(buffer: &[u8]) {
    match Coff::parse(buffer) {
        Ok(coff) => check_all(&coff),
        Err(e) => {
            println!("[!] Failed to parse input as COFF file");
            println!(" -> Error: {:?}", e);
        }
    };
}

fn print_coff(coff: &Coff) {
    println!("COFF header machine type: 0x{:04x}", &coff.header.machine);
    println!("COFF header number of sections: {}", &coff.header.number_of_sections);
    // println!("COFF symbols:");
    // for (_, _, symbol) in coff.symbols.iter() {
    //     let name = symbol.name(&coff.strings).unwrap();
    //     println!(" -> {}", &name);
    // }
    println!("COFF sections:");
    for section in coff.sections.iter() {
        println!(" -> {}", &section.name().unwrap_or("UNKNOWN"));
    }
    println!("COFF imports:");
    for import in get_imports(coff) {
        let name: &str = import.name(&coff.strings).unwrap();
        println!(" -> {}", name);
    }
}

fn get_imports<'a>(coff: &'a Coff) -> impl Iterator<Item=Symbol> + 'a {
    let prefix: &str = match coff.header.machine {
        IMAGE_FILE_MACHINE_I386 => "__imp__",
        IMAGE_FILE_MACHINE_AMD64 => "__imp_",
        _ => panic!("Unsupported machine type")
    };
    coff.symbols.iter()
        .map(|tuple| { tuple.2 })
        .filter(move |s| {
            s.name(&coff.strings).unwrap().starts_with(prefix)
        })
        //.collect()
}

fn check_all(coff: &Coff) {
    check_arch(coff);
    check_entrypoint(coff);
    check_imports(coff);
}

fn check_arch(coff: &Coff) {
    let arch: &str = match coff.header.machine {
        IMAGE_FILE_MACHINE_I386 => "x86",
        IMAGE_FILE_MACHINE_AMD64 => "x64",
        IMAGE_FILE_MACHINE_ARM64 => "aarch64",
        _ => panic!("Unsupported machine type")
    };
    println!("[+] machine arch: {}", &arch);
}

fn check_entrypoint(coff: &Coff) -> () {
    match coff.symbols.iter()
        .map(|tuple| { tuple.2.name(&coff.strings)
            .expect("Unable to read symbol name")
            .to_string()
        })
        .any(|s| s.eq(BEACON_ENTRYPOINT)) {
            true => println!("[+] entrypoint: {}()", BEACON_ENTRYPOINT),
            false => println!("{} {}", "[!] entrypoint not found:".bold().red(), BEACON_ENTRYPOINT.bold().red()),
        }
}

fn check_imports(coff: &Coff) {
    let prefix: &str = match coff.header.machine {
        IMAGE_FILE_MACHINE_I386 => "__imp__",
        IMAGE_FILE_MACHINE_AMD64 => "__imp_",
        _ => panic!("Unsupported machine type")
    };
    coff.symbols.iter()
        .map(|tuple| { tuple.2.name(&coff.strings)
            .expect("Unable to read symbol name")
            .to_string()
        })
        .filter_map(|s| match s.starts_with(prefix) {
            true => Some(s.strip_prefix(prefix).unwrap().to_string()),
            false => None,
        })
        .for_each(|name| {
            if BEACON_EXPORTS.contains(&&name[..]) {
                println!("[+] beacon export: {}", &name);
            } else if WIN32_BUILTIN.contains(&&name[..]) {
                println!("[+] beacon win32 builtin: {}", &name);
            } else if let Some((module, function)) = &name.split('$').next_tuple() {
                // remove suffix from symbol name
                let function = function.split('@').next().unwrap();
                if WIN32_MODULES.contains(module) {
                    println!("[+] dynamic function resolution: {}${}", &module, &function);
                } else {
                    println!("{} {}", "[!] unrecognized win32 library:".bold().red(), &name.bold().red());
                }
            } else {
                println!("{} {}", "[!] unknown import:".bold().red(), &name.bold().red());
            }
        });
}