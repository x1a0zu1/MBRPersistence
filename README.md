# MBRPersistence
Create a boot code for the MBR (Windows 10) that will execute specified Windows executable file during the boot process.
Uses a kernel driver.

**Also includes watchdog**, is a kernel driver that constantly checks for driver tampering / unauthorized debugging.
Does not monitor the main driver but will detect someone trying to RE all related drivers.

## Note

This was not written for malicious purposes, it is an educational example of another way to create persistence
with Windows executables which could potentially be extremely annoying to remove from the computer.
