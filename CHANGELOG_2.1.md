# NAND Fix Pro v2.1 - Release Notes

## What's New

### Offline Mode / File Mode

Version 2.1 introduces a major new feature: **Offline Mode** (File Mode). You can now toggle between **Live Mode** and **Offline Mode** depending on your workflow.

**Live Mode (Original)**
- Works directly with your Switch's eMMC via USB connection
- Requires Hekate's USB Tools (eMMC RAW GPP mode)
- Uses OSFMount to mount partitions

**Offline Mode (New)**
- Works with RAWNAND.bin backup files
- No need for live eMMC connection
- No OSFMount required
- Perfect for working with existing backups or troubleshooting without the console connected

### Key Features

**Offline Mode Workflow**
- Select your RAWNAND.bin backup file directly from disk
- Provide your prod.keys file via file selector (no need to extract from SD card)
- All three repair levels now support offline processing
- Outputs a fixed RAWNAND file (e.g., RAWNAND_FIXED_L1.bin) that you can flash later

**UI Improvements**
- Mode toggle switch to select between Live and Offline modes
- Dynamic UI that adapts based on selected mode
- Buttons and file selectors change automatically when switching modes
- Cleaner workflow with mode-specific requirements

**Level 2 Enhancement**
- New "Advanced: Fix USER Only" button
- Allows repairing just the USER partition without touching other partitions
- Faster alternative for USER-specific corruption issues

**Technical Improvements**
- Enhanced widget validation to prevent UI crashes
- Configuration now saves your mode preference
- Smart file cleanup that preserves user files in Offline mode
- Better error handling and stability

### Dependency Updates

- Added OpenSSL libraries (libcrypto-1_1-x64.dll, libssl-1_1-x64.dll)
- Updated NxNandManager.exe
- Updated dokan1.dll
- Removed dokan driver installation files (no longer needed)

### Bug Fixes

- Fixed potential crashes from destroyed UI widgets
- Improved button state management across mode switches
- Better handling of temporary files in different modes

## When to Use Each Mode

**Use Live Mode when:**
- Your Switch is accessible and can connect via USB
- You want real-time eMMC repair
- You're comfortable with the original workflow

**Use Offline Mode when:**
- Working with existing RAWNAND.bin backups
- Your Switch is not available for direct connection
- You want to test repairs without touching the actual eMMC
- You prefer working with files before committing changes

## Installation

1. Download the release package
2. Extract to your desired location
3. Add Windows Defender exclusion (same as previous versions)
4. Run NANDFixPro.exe

## Requirements

**Live Mode:**
- All previous requirements (Hekate, USB connection, OSFMount)

**Offline Mode:**
- RAWNAND.bin backup file
- prod.keys file
- Firmware folder
- No OSFMount needed
- No live console connection needed

## Upgrade Notes

If upgrading from v2.0.x:
- Your existing configuration will be preserved
- The tool defaults to Live Mode on first launch
- You can switch to Offline Mode anytime via the mode toggle

---

**Full Changelog:**
- Add complete offline/file mode support
- Add mode toggle switch in UI
- Add dynamic UI adaptation based on mode
- Add "Advanced: Fix USER Only" button for Level 2
- Add configuration persistence for mode selection
- Update NxNandManager and dependencies
- Add OpenSSL library support
- Improve widget validation and error handling
- Normalize file line endings
- Remove unused dokan driver files
