#!/usr/bin/env python3
"""
gen_structured_seeds.py — Generate minimal but structurally-valid ISOBMFF seeds
targeting specific box types to maximize parser code coverage.

Each seed is a hand-crafted MP4/HEIF file that exercises a specific parser path.
These are designed to complement mp4gen's random outputs with targeted coverage.

Usage: python3 gen_structured_seeds.py <output_dir>
"""
import struct, os, sys, hashlib

def u32be(v): return struct.pack('>I', v & 0xFFFFFFFF)
def u64be(v): return struct.pack('>Q', v & 0xFFFFFFFFFFFFFFFF)
def box(fourcc, payload=b''): return u32be(8 + len(payload)) + fourcc.encode() + payload
def fullbox(fourcc, version, flags, payload=b''):
    return box(fourcc, bytes([version]) + u32be(flags)[1:] + payload)

def ftyp(brand='isom', minor=0, compat=('isom','iso2','mp41')):
    data = brand.encode()[:4].ljust(4) + u32be(minor)
    for c in compat: data += c.encode()[:4].ljust(4)
    return box('ftyp', data)

def mvhd_v0(timescale=1000, duration=1000):
    return fullbox('mvhd', 0, 0,
        u32be(0)*2 +          # creation/modification time
        u32be(timescale) +
        u32be(duration) +
        u32be(0x00010000) +   # rate 1.0
        struct.pack('>H', 0x0100) +  # volume 1.0
        b'\x00'*10 +          # reserved
        b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # matrix row 1
        b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'  # matrix row 2
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00'  # matrix row 3
        + b'\x00'*24 +        # pre-defined
        u32be(2)              # next_track_ID
    )

def mvhd_v1(timescale=90000, duration=0xFFFFFFFF):
    """Version 1 MVHD with 64-bit timestamps — rarely tested."""
    return fullbox('mvhd', 1, 0,
        u64be(0)*2 +
        u32be(timescale) +
        u64be(duration) +
        u32be(0x00010000) +
        struct.pack('>H', 0x0100) +
        b'\x00'*10 +
        b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00'
        + b'\x00'*24 +
        u32be(2)
    )

def tkhd_v0(track_id=1, duration=1000, width=320, height=240, flags=3):
    return fullbox('tkhd', 0, flags,
        u32be(0)*2 +          # creation/modification time
        u32be(track_id) +
        u32be(0) +            # reserved
        u32be(duration) +
        u32be(0)*2 +          # reserved
        struct.pack('>hH', 0, 0) +  # layer, alternate_group
        struct.pack('>H', 0x0100) + # volume
        u32be(0) +
        b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00'
        + u32be(width << 16) + u32be(height << 16)  # fixed-point width/height
    )

def mdhd_v0(timescale=44100, duration=44100, lang='und'):
    lg = ((ord(lang[0])-0x60)<<10)|((ord(lang[1])-0x60)<<5)|(ord(lang[2])-0x60)
    return fullbox('mdhd', 0, 0,
        u32be(0)*2 + u32be(timescale) + u32be(duration) +
        struct.pack('>H', lg) + struct.pack('>H', 0)
    )

def hdlr(handler_type='vide', name='VideoHandler'):
    return fullbox('hdlr', 0, 0,
        u32be(0) + handler_type.encode() + b'\x00'*12 + name.encode() + b'\x00'
    )

def stsd_avc(width=320, height=240):
    """Sample description with AVC/H.264 box."""
    avcc = box('avcC',
        b'\x01'       # configurationVersion=1
        b'\x64\x00\x1f'  # profile=100 (High), profileCompat, level=31
        b'\xff'       # lengthSizeMinusOne=3 (4-byte NAL lengths)
        b'\xe1'       # numSequenceParameterSets=1
        b'\x00\x1b'   # SPS length=27
        # SPS for 320x240 High profile (simplified)
        b'\x67\x64\x00\x1f\xac\xd9\x40\xa0\x2f\xf9\x70\x11\x00\x00\x03\x00'
        b'\x01\x00\x00\x03\x00\x32\x0f\x16\x2d\x96'
        b'\x01'       # numPictureParameterSets=1
        b'\x00\x06'   # PPS length=6
        b'\x68\xe9\x78\x32\xc8\xb0'
    )
    btrt = box('btrt',
        u32be(0) + u32be(400000) + u32be(400000)  # bufSize, maxBitrate, avgBitrate
    )
    avc1_payload = (
        b'\x00'*6 + struct.pack('>H', 1) +  # reserved + data_ref_index
        b'\x00'*16 +                         # pre-defined/reserved
        struct.pack('>HH', width, height) +
        struct.pack('>II', 0x00480000, 0x00480000) +  # hRes, vRes = 72dpi
        b'\x00'*4 + struct.pack('>H', 1) +   # reserved + frame_count
        b'\x00'*32 + struct.pack('>H', 0x18) + struct.pack('>h', -1) +  # compressor + depth + pre_defined
        avcc + btrt
    )
    entry = box('avc1', avc1_payload)
    return fullbox('stsd', 0, 0, u32be(1) + entry)

def stsd_hevc(width=320, height=240):
    """Sample description with HEVC/H.265 box."""
    hvcc = box('hvcC',
        b'\x01'           # configurationVersion=1
        b'\x01'           # general_profile_space=0, tier=0, profile_idc=1
        b'\x60\x00\x00\x00'  # general_profile_compatibility_flags
        b'\x90\x00\x00\x00\x00\x00'  # general_constraint_indicator_flags
        b'\x5d'           # general_level_idc=93
        b'\xf0\x00'       # min_spatial_segmentation_idc
        b'\xfc'           # parallelismType
        b'\xfd'           # chromaFormat=1 (4:2:0)
        b'\xf8'           # bitDepthLumaMinus8
        b'\xf8'           # bitDepthChromaMinus8
        b'\x00\x00'       # avgFrameRate
        b'\x0f'           # constantFrameRate=0, numTemporalLayers=1, temporalIdNested=1, lengthSizeMinusOne=3
        b'\x00'           # numOfArrays=0
    )
    hvc1_payload = (
        b'\x00'*6 + struct.pack('>H', 1) +
        b'\x00'*16 +
        struct.pack('>HH', width, height) +
        struct.pack('>II', 0x00480000, 0x00480000) +
        b'\x00'*4 + struct.pack('>H', 1) +
        b'\x00'*32 + struct.pack('>H', 0x18) + struct.pack('>h', -1) +
        hvcc
    )
    entry = box('hvc1', hvc1_payload)
    return fullbox('stsd', 0, 0, u32be(1) + entry)

def stsd_mp4a(sample_rate=44100, channels=2):
    """Sample description with AAC audio box."""
    esds_payload = (
        b'\x03'       # ES_Descriptor
        b'\x19'       # length=25
        b'\x00\x01'   # ES_ID=1
        b'\x00'       # streamDependenceFlag etc
        b'\x04'       # DecoderConfigDescriptor
        b'\x11'       # length=17
        b'\x40'       # objectTypeIndication=0x40 (Audio ISO/IEC 14496-3)
        b'\x15'       # streamType=0x15 (audio stream)
        b'\x00\x00\x00'  # bufferSizeDB
        b'\x00\x00\x00\x00'  # maxBitrate
        b'\x00\x00\x00\x00'  # avgBitrate
        b'\x05'       # DecoderSpecificInfo
        b'\x02'       # length=2
        b'\x12\x10'   # AudioSpecificConfig: AAC-LC, 44100Hz, stereo
        b'\x06'       # SLConfigDescriptor
        b'\x01'       # length=1
        b'\x02'       # predefined=2
    )
    esds = fullbox('esds', 0, 0, esds_payload)
    mp4a_payload = (
        b'\x00'*6 + struct.pack('>H', 1) +
        b'\x00'*8 +
        struct.pack('>H', channels) +
        struct.pack('>H', 0x10) +  # sampleSize=16
        b'\x00\x00' + b'\x00\x00' +
        struct.pack('>I', sample_rate << 16) +
        esds
    )
    entry = box('mp4a', mp4a_payload)
    return fullbox('stsd', 0, 0, u32be(1) + entry)

def stts(entries=[(1,1)]):
    """Sample-to-time table."""
    data = u32be(len(entries))
    for count, delta in entries: data += u32be(count) + u32be(delta)
    return fullbox('stts', 0, 0, data)

def ctts(entries, version=0):
    """Composition time offset — version 0 (unsigned) or 1 (signed, for B-frames)."""
    data = u32be(len(entries))
    for count, offset in entries: data += u32be(count) + u32be(offset & 0xFFFFFFFF)
    return fullbox('ctts', version, 0, data)

def stsc(entries=[(1,1,1)]):
    """Sample-to-chunk."""
    data = u32be(len(entries))
    for fc, spc, sdi in entries: data += u32be(fc) + u32be(spc) + u32be(sdi)
    return fullbox('stsc', 0, 0, data)

def stsz(sample_size=0, sizes=None):
    """Sample sizes."""
    if sizes:
        data = u32be(0) + u32be(len(sizes))
        for s in sizes: data += u32be(s)
    else:
        data = u32be(sample_size) + u32be(1)
    return fullbox('stsz', 0, 0, data)

def stco(offsets=[8]):
    data = u32be(len(offsets))
    for o in offsets: data += u32be(o)
    return fullbox('stco', 0, 0, data)

def co64(offsets=[8]):
    data = u32be(len(offsets))
    for o in offsets: data += u64be(o)
    return fullbox('co64', 0, 0, data)

def stss(sample_numbers=[1]):
    data = u32be(len(sample_numbers))
    for n in sample_numbers: data += u32be(n)
    return fullbox('stss', 0, 0, data)

def elst(entries, version=0):
    """Edit list box."""
    data = u32be(len(entries))
    for seg_dur, media_time, rate in entries:
        if version == 0:
            data += u32be(seg_dur) + struct.pack('>i', media_time) + u32be(rate)
        else:
            data += u64be(seg_dur) + struct.pack('>q', media_time) + u32be(rate)
    return fullbox('elst', version, 0, data)

def trex(track_id=1):
    return fullbox('trex', 0, 0,
        u32be(track_id) +  # default_sample_description_index
        u32be(1) +         # default_sample_description_index
        u32be(0) +         # default_sample_duration
        u32be(0) +         # default_sample_size
        u32be(0)           # default_sample_flags
    )

def mfhd(seq=1):
    return fullbox('mfhd', 0, 0, u32be(seq))

def tfhd(track_id=1, base_data_offset=None, flags=0):
    data = u32be(track_id)
    if base_data_offset is not None:
        flags |= 0x000001
        data += u64be(base_data_offset)
    return fullbox('tfhd', 0, flags, data)

def tfdt(base_decode_time=0, version=0):
    if version == 1:
        return fullbox('tfdt', 1, 0, u64be(base_decode_time))
    return fullbox('tfdt', 0, 0, u32be(base_decode_time))

def trun(samples, flags=0x301):
    """Track run: flags=0x301 = data_offset_present + sample_duration_present."""
    data = u32be(len(samples)) + struct.pack('>i', 0)  # data_offset=0
    for dur, size in samples:
        data += u32be(dur) + u32be(size)
    return fullbox('trun', 0, flags, data)

def pssh(system_id=b'\xa2\x39\x4f\x52\x5a\x9b\x4f\x14\xa2\x44\x6c\x42\x7c\x64\x8d\xf4'):
    """Protection System Specific Header box."""
    kid_count = 1
    kid = b'\x00'*16
    data = (system_id[:16].ljust(16, b'\x00') +
            u32be(kid_count) + kid +
            u32be(4) + b'FAKE')   # pssh_data
    return fullbox('pssh', 1, 0, data)

def sinf(original_format='mp4a'):
    """Protection scheme info container."""
    frma = box('frma', original_format.encode()[:4].ljust(4))
    schm = fullbox('schm', 0, 0, b'cenc' + u32be(0x00010000))
    tenc = fullbox('tenc', 0, 0,
        b'\x00\x00' +  # reserved
        b'\x01' +      # isEncrypted=1
        b'\x08' +      # IV_size=8
        b'\x00'*16     # default_KID
    )
    schi = box('schi', tenc)
    return box('sinf', frma + schm + schi)

def colr(primaries=1, transfer=1, matrix=1, full_range=False):
    return box('colr',
        b'nclx' +
        struct.pack('>HHH', primaries, transfer, matrix) +
        bytes([0x80 if full_range else 0x00])
    )

def pasp(h_spacing=1, v_spacing=1):
    return box('pasp', u32be(h_spacing) + u32be(v_spacing))

def minimal_video_track(track_id=1, timescale=90000, duration=90000,
                        width=320, height=240, stsd_box=None,
                        extra_boxes=b'', flags=3):
    if stsd_box is None: stsd_box = stsd_avc(width, height)
    stbl_content = (
        stsd_box +
        stts([(1, 90000)]) +
        stsc([(1,1,1)]) +
        stsz(100) +
        stco([28])
    )
    stbl = box('stbl', stbl_content)
    minf_content = box('vmhd', b'\x00'*8) + box('dinf', fullbox('dref', 0, 0, u32be(1) + fullbox('url ', 0, 1, b''))) + stbl
    mdia_content = mdhd_v0(timescale, duration) + hdlr('vide') + box('minf', minf_content)
    edts = box('edts', elst([(duration, 0, 0x00010000)]))
    trak_content = tkhd_v0(track_id, duration, width, height, flags) + edts + box('mdia', mdia_content) + extra_boxes
    return box('trak', trak_content)

def minimal_audio_track(track_id=2, sample_rate=44100):
    stbl_content = (
        stsd_mp4a(sample_rate) +
        stts([(1024, 1)]) +
        stsc([(1,1,1)]) +
        stsz(0, [128]*10) +
        stco([28])
    )
    stbl = box('stbl', stbl_content)
    minf_content = fullbox('smhd', 0, 0, b'\x00'*4) + box('dinf', fullbox('dref', 0, 0, u32be(1) + fullbox('url ', 0, 1, b''))) + stbl
    mdia_content = mdhd_v0(sample_rate, sample_rate) + hdlr('soun') + box('minf', minf_content)
    trak_content = tkhd_v0(track_id, 1000, 0, 0) + box('mdia', mdia_content)
    return box('trak', trak_content)

def write_seed(outdir, name, data):
    h = hashlib.md5(data).hexdigest()[:8]
    path = os.path.join(outdir, f'struct_{name}_{h}.mp4')
    with open(path, 'wb') as f: f.write(data)
    return path

def gen_seeds(outdir):
    os.makedirs(outdir, exist_ok=True)
    seeds = []

    # 1. Minimal valid ftyp+moov (video only)
    moov = box('moov', mvhd_v0() + minimal_video_track())
    seeds.append(('minimal_av', ftyp() + box('mdat', b'\x00'*16) + moov))

    # 2. Version-1 MVHD (64-bit timestamps)
    moov = box('moov', mvhd_v1() + minimal_video_track())
    seeds.append(('mvhd_v1', ftyp('isom') + box('mdat', b'\x00'*16) + moov))

    # 3. HEVC video track
    moov = box('moov', mvhd_v0() + minimal_video_track(stsd_box=stsd_hevc()))
    seeds.append(('hevc_track', ftyp('isom', 0, ('isom','hvc1')) + box('mdat', b'\x00'*16) + moov))

    # 4. Audio+video tracks
    moov = box('moov', mvhd_v0() + minimal_video_track(1) + minimal_audio_track(2))
    seeds.append(('av_tracks', ftyp() + box('mdat', b'\x00'*100) + moov))

    # 5. CTTS v0 (unsigned composition offsets — delayed B-frames)
    ctts_v0 = ctts([(30, 1001), (1, 0)], version=0)
    moov = box('moov', mvhd_v0() + minimal_video_track(extra_boxes=b'', stsd_box=stsd_avc()))
    # inject ctts into stbl
    stbl_with_ctts = (stsd_avc() + stts([(30, 3000)]) + ctts_v0 +
                      stsc([(1,1,1)]) + stsz(100) + stco([28]))
    stbl = box('stbl', stbl_with_ctts)
    minf = box('vmhd', b'\x00'*8) + box('dinf', fullbox('dref', 0, 0, u32be(1) + fullbox('url ', 0, 1, b''))) + stbl
    mdia = mdhd_v0() + hdlr('vide') + box('minf', minf)
    trak = tkhd_v0(1, 90000) + box('mdia', mdia)
    moov = box('moov', mvhd_v0() + box('trak', trak))
    seeds.append(('ctts_v0', ftyp() + box('mdat', b'\x00'*100) + moov))

    # 6. CTTS v1 (signed — negative offsets)
    ctts_v1 = ctts([(10, 0xFFFFFFFF), (10, 1), (10, 0xFFFFFFFE)], version=1)
    stbl_with_ctts = (stsd_avc() + stts([(30, 3000)]) + ctts_v1 +
                      stsc([(1,1,1)]) + stsz(100) + stco([28]))
    stbl = box('stbl', stbl_with_ctts)
    minf = box('vmhd', b'\x00'*8) + box('dinf', fullbox('dref', 0, 0, u32be(1) + fullbox('url ', 0, 1, b''))) + stbl
    mdia = mdhd_v0() + hdlr('vide') + box('minf', minf)
    trak = tkhd_v0(1, 90000) + box('mdia', mdia)
    moov = box('moov', mvhd_v0() + box('trak', trak))
    seeds.append(('ctts_v1_neg', ftyp() + box('mdat', b'\x00'*100) + moov))

    # 7. CO64 (64-bit chunk offsets)
    stbl_co64 = stsd_avc() + stts([(1,1)]) + stsc([(1,1,1)]) + stsz(100) + co64([28])
    stbl = box('stbl', stbl_co64)
    minf = box('vmhd', b'\x00'*8) + box('dinf', fullbox('dref', 0, 0, u32be(1) + fullbox('url ', 0, 1, b''))) + stbl
    mdia = mdhd_v0() + hdlr('vide') + box('minf', minf)
    trak = tkhd_v0(1, 1000) + box('mdia', mdia)
    moov = box('moov', mvhd_v0() + box('trak', trak))
    seeds.append(('co64', ftyp() + box('mdat', b'\x00'*16) + moov))

    # 8. Fragmented MP4 (moof+mdat)
    trex_box = trex(1)
    mvex_box = box('mvex', trex_box)
    moov = box('moov', mvhd_v0() + minimal_video_track() + mvex_box)
    frag_header = ftyp('isom', 0, ('isom','iso5','dash'))
    moof_box = box('moof', mfhd(1) + box('traf', tfhd(1) + tfdt(0) + trun([(3000,100),(3000,80)])))
    moof2 = box('moof', mfhd(2) + box('traf', tfhd(1) + tfdt(3000) + trun([(3000,90)])))
    seeds.append(('fragmented', frag_header + moov + moof_box + box('mdat', b'\x00'*180) + moof2 + box('mdat', b'\x00'*90)))

    # 9. Fragmented with TFDT v1 (64-bit decode time)
    moof_v1 = box('moof', mfhd(1) + box('traf', tfhd(1) + tfdt(0, version=1) + trun([(3000,100)])))
    seeds.append(('frag_tfdt_v1', frag_header + moov + moof_v1 + box('mdat', b'\x00'*100)))

    # 10. Edit list v0 (empty edit then content)
    elst_empty = box('edts', elst([(-1, -1, 0x00010000), (90000, 0, 0x00010000)], version=0))
    stbl_c = stsd_avc() + stts([(1, 90000)]) + stsc([(1,1,1)]) + stsz(100) + stco([28])
    stbl = box('stbl', stbl_c)
    minf = box('vmhd', b'\x00'*8) + box('dinf', fullbox('dref', 0, 0, u32be(1) + fullbox('url ', 0, 1, b''))) + stbl
    mdia = mdhd_v0(90000, 90000) + hdlr('vide') + box('minf', minf)
    trak = tkhd_v0(1, 90000) + elst_empty + box('mdia', mdia)
    moov = box('moov', mvhd_v0() + box('trak', trak))
    seeds.append(('elst_empty_edit', ftyp() + box('mdat', b'\x00'*100) + moov))

    # 11. Edit list v1 (64-bit)
    elst_v1 = box('edts', elst([(90000, 0, 0x00010000)], version=1))
    trak = tkhd_v0(1, 90000) + elst_v1 + box('mdia', mdhd_v0(90000,90000) + hdlr('vide') + box('minf', box('vmhd',b'\x00'*8) + box('dinf', fullbox('dref',0,0,u32be(1)+fullbox('url ',0,1,b''))) + box('stbl', stsd_avc() + stts([(1,90000)]) + stsc([(1,1,1)]) + stsz(100) + stco([28]))))
    moov = box('moov', mvhd_v1() + box('trak', trak))
    seeds.append(('elst_v1', ftyp() + box('mdat', b'\x00'*100) + moov))

    # 12. Multiple STTS entries (variable frame durations)
    stts_var = stts([(10, 3000), (5, 1500), (1, 0), (14, 3001)])
    stbl_c = stsd_avc() + stts_var + stsc([(1,1,1)]) + stsz(0, [100]*30) + stco([28])
    stbl = box('stbl', stbl_c)
    minf = box('vmhd', b'\x00'*8) + box('dinf', fullbox('dref',0,0,u32be(1)+fullbox('url ',0,1,b''))) + stbl
    mdia = mdhd_v0(90000,90000) + hdlr('vide') + box('minf', minf)
    trak = tkhd_v0(1, 90000) + box('mdia', mdia)
    moov = box('moov', mvhd_v0() + box('trak', trak))
    seeds.append(('stts_variable', ftyp() + box('mdat', b'\x00'*100) + moov))

    # 13. PSSH + encrypted track
    enc_stsd = sinf() + stsd_avc()
    moov = box('moov', mvhd_v0() + minimal_video_track() + pssh())
    seeds.append(('pssh_encrypted', ftyp('isom',0,('isom','cenc')) + box('mdat',b'\x00'*100) + moov))

    # 14. colr box variations
    for (p,t,m,fr,name_sfx) in [(1,1,1,False,'bt709'), (9,16,9,False,'bt2020_pq'), (1,13,1,True,'srgb')]:
        stbl_c = stsd_avc() + colr(p,t,m,fr) + stts([(1,90000)]) + stsc([(1,1,1)]) + stsz(100) + stco([28])
        stbl = box('stbl', stbl_c)
        minf = box('vmhd',b'\x00'*8) + box('dinf',fullbox('dref',0,0,u32be(1)+fullbox('url ',0,1,b''))) + stbl
        mdia = mdhd_v0() + hdlr('vide') + box('minf', minf)
        trak = tkhd_v0(1,90000) + box('mdia', mdia)
        moov = box('moov', mvhd_v0() + box('trak', trak))
        seeds.append((f'colr_{name_sfx}', ftyp() + box('mdat',b'\x00'*100) + moov))

    # 15. Moov-before-mdat (faststart) vs mdat-before-moov
    moov = box('moov', mvhd_v0() + minimal_video_track())
    mdat = box('mdat', b'\x00'*16)
    seeds.append(('mdat_first', ftyp() + mdat + moov))
    seeds.append(('moov_first', ftyp() + moov + mdat))

    # 16. Zero-duration track
    stbl_c = stsd_avc() + stts([]) + stsc([]) + stsz(0, []) + stco([])
    stbl = box('stbl', stbl_c)
    minf = box('vmhd',b'\x00'*8) + box('dinf',fullbox('dref',0,0,u32be(1)+fullbox('url ',0,1,b''))) + stbl
    mdia = mdhd_v0(90000, 0) + hdlr('vide') + box('minf', minf)
    trak = tkhd_v0(1, 0) + box('mdia', mdia)
    moov = box('moov', mvhd_v0(1000, 0) + box('trak', trak))
    seeds.append(('zero_duration', ftyp() + moov))

    # 17. Subtitle track (tx3g/mov_text)
    TX3G_EXTRA = bytes([
        0,0,0,0, 0,0,0,1, 0,0,0,0, 0,0,0,0,
        1, 0xFF, 0,0,0,0, 0,0,0,0, 0,0,0,0
    ])
    tx3g_entry = (
        b'\x00'*6 + struct.pack('>H', 1) +
        u32be(0)*4 + u32be(0x00000001) +
        u32be(1) + struct.pack('>HH', 1280, 60) +
        TX3G_EXTRA
    )
    tx3g_stsd = fullbox('stsd', 0, 0, u32be(1) + box('tx3g', tx3g_entry))
    stbl_sub = tx3g_stsd + stts([(1,0)]) + stsc([]) + stsz(0,[]) + stco([])
    minf_sub = fullbox('sthd', 0, 0, b'\x00'*8) + box('dinf',fullbox('dref',0,0,u32be(1)+fullbox('url ',0,1,b''))) + box('stbl', stbl_sub)
    mdia_sub = mdhd_v0(1000,0,'eng') + hdlr('text','SubtitleHandler') + box('minf', minf_sub)
    trak_sub = tkhd_v0(3,0,1280,60, flags=AV_DISPOSITION_HEARING_IMPAIRED if False else 3) + box('mdia', mdia_sub)
    moov_sub = box('moov', mvhd_v0() + minimal_video_track(1) + minimal_audio_track(2) + box('trak', trak_sub))
    seeds.append(('subtitle_tx3g', ftyp() + box('mdat',b'\x00'*16) + moov_sub))

    # 18. Deeply nested boxes (stress test for depth limits)
    inner = box('mdat', b'deep')
    for tag in ['traf','trak','mdia','minf','stbl','dinf','udta','meta']:
        inner = box(tag, inner)
    seeds.append(('deep_nesting', ftyp() + inner))

    # 19. ftyp with many compatible brands
    many_brands = ftyp('isom', 0, ['isom','iso2','iso4','iso5','iso6','mp41','mp42','avc1','hvc1','dash','M4V ','M4A ','avif','heic','mif1','msf1'])
    moov = box('moov', mvhd_v0())
    seeds.append(('many_brands', many_brands + moov))

    # 20. Box with extended 64-bit size (largesize)
    # Header: size=1 (signal), type, 64-bit actual size
    payload = b'\x00'*16
    ext_size = struct.pack('>Q', 24)  # 8+8+8 = 24 bytes
    ext_box = u32be(1) + b'free' + ext_size + payload
    moov = box('moov', mvhd_v0())
    seeds.append(('extended_size', ftyp() + ext_box + moov))

    # Write all seeds
    for name, data in seeds:
        path = write_seed(outdir, name, data)
        print(f'  {os.path.basename(path)} ({len(data)}B)')

    print(f'\n[+] Generated {len(seeds)} structured seeds in {outdir}')
    return len(seeds)

if __name__ == '__main__':
    outdir = sys.argv[1] if len(sys.argv) > 1 else '/results/seeds_ok'
    gen_seeds(outdir)
