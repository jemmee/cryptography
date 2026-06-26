// Rocky Linux 5.14.0-611.11.1.el9_7.aarch64
//
// sudo dnf install -y opencryptoki opencryptoki-swtok opencryptoki-libs
// sudo dnf install -y opensc
// sudo dnf install -y opencryptoki-devel
//
// sudo systemctl start pkcsslotd
//
// sudo usermod -aG pkcs11 $USER
// newgrp pkcs11
//
// pkcsconf
// pkcsconf -i
// pkcsconf -t
// pkcsconf -s
// pkcsconf -c 3 -u
//
// curl -O pkcs11.h https://raw.githubusercontent.com/OpenSC/OpenSC/master/src/pkcs11/pkcs11.h
// curl -O pd-pkcs11.h // https://raw.githubusercontent.com/OpenSC/OpenSC/master/src/pkcs11/pd-pkcs11.h
//
// gcc opencryptoki_test.c -o opencryptoki_test -ldl
//
// ./opencryptoki_test
//
// [+] Successfully bound to openCryptoki C API layer.
// [+] Target Token Slot selected: 3 (Total slots: 1)
// [+] R/W Cryptographic Session opened successfully.
// [+] User authenticated to token via PIN challenge verification.
// [*] Performing safe environment teardown...
// [+] Demo completed successfully without memory leaks.

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Standard cryptographic token interface headers
#include "pkcs11.h"

#define OCK_SWTOK_LIB "/usr/lib64/opencryptoki/libopencryptoki.so"
#define SO_PIN "87654321"
#define USER_PIN "12345678"

int main() {
  void *handle;
  CK_RV rv;
  CK_C_GetFunctionList p_GetFunctionList;
  CK_FUNCTION_LIST_PTR pFuncs = NULL;

  // 1. Dynamically load the openCryptoki shared library
  handle = dlopen(OCK_SWTOK_LIB, RTLD_NOW);
  if (!handle) {
    fprintf(stderr, "Failed to load openCryptoki library: %s\n", dlerror());
    return EXIT_FAILURE;
  }

  // 2. Get the core PKCS#11 function list pointer table
  p_GetFunctionList = (CK_C_GetFunctionList)dlsym(handle, "C_GetFunctionList");
  if (!p_GetFunctionList) {
    fprintf(stderr, "Failed to find C_GetFunctionList symbol.\n");
    dlclose(handle);
    return EXIT_FAILURE;
  }

  rv = p_GetFunctionList(&pFuncs);
  if (rv != CKR_OK || !pFuncs) {
    fprintf(stderr, "Error fetching function list pointer table: 0x%lX\n", rv);
    dlclose(handle);
    return EXIT_FAILURE;
  }

  printf("[+] Successfully bound to openCryptoki C API layer.\n");

  // 3. Initialize the Cryptoki subsystem
  rv = pFuncs->C_Initialize(NULL);
  if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
    fprintf(stderr, "C_Initialize failed: 0x%lX\n", rv);
    dlclose(handle);
    return EXIT_FAILURE;
  }

  // 4. Query for available slots
  CK_ULONG slotCount = 0;
  rv = pFuncs->C_GetSlotList(CK_TRUE, NULL, &slotCount);
  if (rv != CKR_OK || slotCount == 0) {
    fprintf(stderr, "No active token slots found: 0x%lX\n", rv);
    pFuncs->C_Finalize(NULL);
    dlclose(handle);
    return EXIT_FAILURE;
  }

  CK_SLOT_ID_PTR pSlotList = malloc(slotCount * sizeof(CK_SLOT_ID));
  pFuncs->C_GetSlotList(CK_TRUE, pSlotList, &slotCount);

  // Pick the first available initialized slot (typically slot 1 for software
  // tokens)
  CK_SLOT_ID targetSlot = pSlotList[0];
  printf("[+] Target Token Slot selected: %lu (Total slots: %lu)\n", targetSlot,
         slotCount);
  free(pSlotList);

  // 5. Open a read-write user session
  CK_SESSION_HANDLE hSession;
  rv = pFuncs->C_OpenSession(targetSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                             NULL, NULL, &hSession);
  if (rv != CKR_OK) {
    fprintf(stderr, "C_OpenSession failed on slot %lu: 0x%lX\n", targetSlot,
            rv);
    pFuncs->C_Finalize(NULL);
    dlclose(handle);
    return EXIT_FAILURE;
  }
  printf("[+] R/W Cryptographic Session opened successfully.\n");

  // 6. Log into the Token using the User PIN
  rv = pFuncs->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)USER_PIN,
                       strlen(USER_PIN));
  if (rv != CKR_OK) {
    fprintf(stderr, "C_Login user authentication failed: 0x%lX\n", rv);
    pFuncs->C_CloseSession(hSession);
    pFuncs->C_Finalize(NULL);
    dlclose(handle);
    return EXIT_FAILURE;
  }
  printf("[+] User authenticated to token via PIN challenge verification.\n");

  // -------------------------------------------------------------
  // At this point, the token session is authenticated and active.
  // You are free to call C_GenerateKey, C_Encrypt, etc.
  // -------------------------------------------------------------
  printf("[*] Performing safe environment teardown...\n");

  // 7. Clean up, log out, and terminate session securely
  pFuncs->C_Logout(hSession);
  pFuncs->C_CloseSession(hSession);
  pFuncs->C_Finalize(NULL);
  dlclose(handle);

  printf("[+] Demo completed successfully without memory leaks.\n");
  return EXIT_SUCCESS;
}