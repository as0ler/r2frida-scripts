'use strict';

const getFunction = (symbol, ret, args) =>
  new NativeFunction(Module.findExportByName(null, symbol), ret, args)

const open = getFunction('open', 'int', ['pointer', 'int', 'int'])
const close = getFunction('close', 'int', ['int'])
const read = getFunction('read', 'int', ['int', 'pointer', 'int'])
const write = getFunction('write', 'int', ['int', 'pointer', 'int'])
const lseek = getFunction('lseek', 'int64', ['int', 'int64', 'int'])
const unlink = getFunction('unlink', 'int', ['pointer'])

const O_RDONLY = 0
const O_RDWR = 2
const SEEK_SET = 0
const PROT_READ = 0x1
const PROT_WRITE = 0x2
const MAP_SHARED = 0x1
const MAP_PRIVATE = 0x2

const commands = {
  'decrypt': decrypt,
  'analyze*': analyzeR2,
  'analyzej': analyze
};

r2frida.pluginRegister('r2flutch', function (name) {
  return commands[name];
});

async function analyzeR2(args) {
  const flags = await analyze(args);
  return flags.map(flag => {
    return `f ${flag.name} = ${flag.addr};`;
  }).join('\n');
}

function analyze(args) {
  return new Promise((resolve, reject) => {
    let flags = [];

    const baseAddr = checkIsValidMacho();
    if (!baseAddr) {
      reject('Error');
    }
    const header = parseMachoHeader(baseAddr, flags);
    if (!header) {
      reject('Error');
    }
    const segments = getSegments(baseAddr, header.ncmds, flags);
    segments.forEach((segment) => {
      if(segment.name == '__TEXT') {
        getSections(segment, flags);
      }
    });
    const encryption_info = getEncryptionInfo(baseAddr, header.ncmds, flags);
    resolve(flags);
  });
}

function getApplicationContent(path) {

}

function decrypt (args) {
  let complete = 0;
  const result = [];
  const baseAddr = checkIsValidMacho();
  console.log('[+] Decrypting application ' + module['name'] + ' at ' + baseAddr);
  
  
  console.log('[*] All Done!');
  return;
}

function checkIsValidMacho() {
  let module = Process.enumerateModules()[0];
  let baseAddr = module['base'];
  if (!isMachoHeaderAtOffset(baseAddr)) {
    console.error('[X] Not a Macho header at ' + baseAddr);
    return null; 
  }
  return baseAddr;
}

function isMachoHeaderAtOffset(offset) { 
  let cursor = trunc4k(offset);
  if (cursor.readU32() == 0xfeedfacf) {
    return true;
  }
  return false;
} 

function parseMachoHeader(offset, flags) {
  console.log('[*] Parsing Macho header at addr: ' + offset);
  let header = { 
    magic: offset.readU32(),
    cputype: offset.add(0x4).readU32(),
    cpusubtype: offset.add(0x8).readU32(),
    filetype: offset.add(0x0c).readU32(),
    ncmds: offset.add(0x10).readU32(),
    sizeofcmds: offset.add(0x14).readU32(),
    flags: offset.add(0x18).readU32(),
  };
  if (header.cputype !== 0x0100000c) {
    console.error('[X] sorry not a 64-bit app');
    return null;
  }
  flags.push({
    name: 'macho_header',
    addr: offset
  });
  return header;
}

function getSegments (baseAddr, ncmds, flags) {
  let cursor = baseAddr.add(0x20);
  let LC_SEGMENT_64 = 0x19;
  let segs = [];
  let slide = 0;
  while (ncmds-- > 0) {
    let command = cursor.readU32();
    let cmdSize = cursor.add(4).readU32();
    if (command !== LC_SEGMENT_64) {
      cursor = cursor.add(cmdSize);
      continue;
    }
    let seg = {
      name: cursor.add(0x8).readUtf8String(),
      vmaddr: cursor.add(0x18).readPointer(),
      vmsize: cursor.add(0x18).add(8).readPointer(),
      nsects: cursor.add(64).readU32(),
      sections: cursor.add(72)
    };
    if (seg.name === '__TEXT') {
      slide = baseAddr.sub(seg.vmaddr);
    }
    cursor = cursor.add(cmdSize);
    segs.push(seg);
  }
  segs.forEach((seg) => {
    if (seg.name != '__PAGEZERO') {
      console.log('[*] Segment ' + seg.name + ' found at ' + seg.vmaddr);
      seg.vmaddr = seg.vmaddr.add(slide);
      seg.slide = slide;
      flags.push({
        name: `segment.${seg.name}`,
        addr: seg.vmaddr
      });
    }
  });
  return segs;
}

function getSections (segment, flags) {
  let { nsects, sections, slide } = segment;
  const sects = [];
  while (nsects--) {
    sects.push({
      name: sections.readUtf8String(),
      vmaddr: sections.add(32).readPointer().add(slide),
      vmsize: sections.add(40).readU64()
    });
    sections = sections.add(80);
  }
  sects.forEach((section) => {
    console.log('[*] Section ' + section.name + ' found at ' + section.vmaddr);
    flags.push({
      name: `section.${section.name}`,
      addr: section.vmaddr
    });
  });
  return sects;
}

function getEncryptionInfo(baseAddr, ncmds) {
  let cursor = baseAddr.add(0x20);
  let LC_ENCRYPTION_INFO_64 = 0x2C;
  let encryption_info = "";
  while (ncmds-- > 0) {
    let command = cursor.readU32();
    let cmdSize = cursor.add(4).readU32();
    if (command !== LC_ENCRYPTION_INFO_64) {
      cursor = cursor.add(cmdSize);
      continue;
    }
    console.log('[*] Detected LC_ENCRYPTION_INFO_64 at ' + cursor);
    encryption_info = {
      cryptoff: cursor.add(0x8).readU32(),
      cryptsize: cursor.add(0xc).readU32(),
      cryptid: cursor.add(0x10).readU32(),
    };
    cursor = cursor.add(cmdSize);
  }
  return encryption_info;
}

function trunc4k (x) {
  return x.and(ptr('0xfff').not());
}

function copyApplication(source_path, destination_path) {
  return true;
}

function dump(moduleAddr, cryptoff, cryptsize) {
  const err = Memory.alloc(Process.pointerSize)
  const fileManager = ObjC.classes.NSFileManager.defaultManager()
  if (fileManager.fileExistsAtPath_(tmp))
    fileManager.removeItemAtPath_error_(tmp, err)
  fileManager.copyItemAtPath_toPath_error_(module.path, tmp, err)
  const desc = Memory.readPointer(err)
  if (!desc.isNull()) {
    console.error(`failed to copy file: ${new ObjC.Object(desc).toString()}`)
    return null
  }

  const output = Memory.allocUtf8String(tmp)
  const outfd = open(output, O_RDWR, 0)
  const fatOffset = Process.findRangeByAddress(module.base).file.offset

  lseek(outfd, fatOffset + encryptionInfo.offset, SEEK_SET)
  write(outfd, module.base.add(encryptionInfo.offset), encryptionInfo.size)

  const zeros = Memory.alloc(12)
  lseek(outfd, fatOffset + encryptionInfo.fileoff + 8, SEEK_SET)
  write(outfd, zeros, 12)
  close(outfd)


  lseek(outfd, fatOffset + encryptionInfo.offset, SEEK_SET)
  write(outfd, module.base.add(encryptionInfo.offset), encryptionInfo.size)
}