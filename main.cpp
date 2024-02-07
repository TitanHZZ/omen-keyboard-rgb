#define _WIN32_DCOM

#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

static int Execute(int command, int commandType, int inputDataSize, BYTE* inputData, int* returnDataSize, BYTE** returnData) {
    // magic constant
    static const BYTE Sign[4] = { 83, 69, 67, 85 };

    // will hold the return codes from all the calls to WMI
    HRESULT hres;

    // initialize COM interface
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize COM interface. Got error code = 0x" << std::hex << hres << std::endl;
        return 1;
    }

    // initialize WMI security
    hres = CoInitializeSecurity(
        NULL,
        -1,   // COM negotiates service
        NULL, // Authentication services
        NULL, // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // authentication
        RPC_C_IMP_LEVEL_IMPERSONATE, // Impersonation
        NULL,      // Authentication info
        EOAC_NONE, // Additional capabilities
        NULL       // Reserved
    );

    if (FAILED(hres)) {
        std::cerr << "Failed to initialize WMI security. Got error code = 0x" << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;
    }

    // obtain the initial locator to the Windows Management Instrumentation
    IWbemLocator* pLoc = nullptr;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*) &pLoc );
    if (FAILED(hres)) {
        std::cerr << "Failed to create IWbemLocator locator object. Got error code = 0x" << std::hex << hres << std::endl;
        CoUninitialize();
        return 1;
    }

    IWbemServices* pSvc = nullptr;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\WMI"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        std::cerr << "Could not connect. Error code = 0x" << std::hex << hres << std::endl;
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
        NULL,                        // Server principal name
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities
    );

    if (FAILED(hres)) {
        std::cerr << "Could not set proxy blanket. Got error code = 0x" << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    //// Get all the required custom hp wmi obejcts ////

    IWbemClassObject* classObject = nullptr;
    hres = pSvc->GetObject(_bstr_t(L"hpqBIntM"), 0, NULL, &classObject, NULL);
    if (FAILED(hres)) {
        std::cerr<< "Failed to get retrieve the 'ACPI\\PNP0C14\\0_0' instance from the 'hpqBIntM' class. Got error code = 0x" << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    IWbemClassObject* methodParameters = nullptr;
    hres = classObject->GetMethod(L"hpqBIOSInt128", 0, &methodParameters, NULL);
    if (FAILED(hres)) {
        std::cerr << "Failed to get input parameter object for the method 'hpqBIOSInt128' from the class 'hpqBIntM'. Got error code = 0x" << std::hex << hres << std::endl;
        classObject->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    IWbemClassObject* dataInClass = nullptr;
    hres = pSvc->GetObject(_bstr_t(L"hpqBDataIn"), 0, NULL, &dataInClass, NULL);
    if (FAILED(hres)) {
        std::cerr << "Failed to get input parameters object, instance of the 'hpqBDataIn' class. Got error code = 0x" << std::hex << hres << std::endl;
        methodParameters->Release();
        classObject->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    IWbemCallResult* callResult = nullptr;
    // IWbemClassObject* dataOutClass = nullptr;
    hres = pSvc->GetObject(_bstr_t(L"hpqBDataOut128"), 0, NULL, NULL, &callResult);
    if (FAILED(hres)) {
        std::cerr << "Failed to get instance of the 'hpqBDataOut128' class. Got error code = 0x" << std::hex << hres << std::endl;
        dataInClass->Release();
        methodParameters->Release();
        classObject->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    //// Populate the input parameters ////

    // Sign
    VARIANT signVar;
    VariantInit(&signVar);
    signVar.vt = VT_UI1 | VT_ARRAY;
    SAFEARRAYBOUND safeArrayBound = { 4, 0 };
    signVar.parray = SafeArrayCreate(VT_UI1, 1, &safeArrayBound);
    SafeArrayLock(signVar.parray);
    memcpy(signVar.parray->pvData, Sign, sizeof(Sign));
    SafeArrayUnlock(signVar.parray);
    dataInClass->Put(L"Sign", 0, &signVar, 0);
    VariantClear(&signVar);

    // Command
    VARIANT commandVar;
    VariantInit(&commandVar);
    commandVar.vt = VT_I4;
    commandVar.lVal = command;
    dataInClass->Put(L"Command", 0, &commandVar, 0);
    VariantClear(&commandVar);

    // CommandType
    VARIANT commandTypeVar;
    VariantInit(&commandTypeVar);
    commandTypeVar.vt = VT_I4;
    commandTypeVar.lVal = commandType;
    dataInClass->Put(L"CommandType", 0, &commandTypeVar, 0);
    VariantClear(&commandTypeVar);

    // Size
    VARIANT sizeVar;
    VariantInit(&sizeVar);
    sizeVar.vt = VT_I4;
    sizeVar.lVal = inputDataSize;
    dataInClass->Put(L"Size", 0, &sizeVar, 0);

    // hpqBData
    VARIANT hpqBDataVar;
    VariantInit(&hpqBDataVar);
    hpqBDataVar.vt = VT_UI1 | VT_ARRAY;
    SAFEARRAYBOUND safeArrayBoundData = { static_cast<ULONG>(inputDataSize), 0 };
    hpqBDataVar.parray = SafeArrayCreate(VT_UI1, 1, &safeArrayBoundData);
    SafeArrayLock(hpqBDataVar.parray);
    memcpy(hpqBDataVar.parray->pvData, inputData, inputDataSize);
    SafeArrayUnlock(hpqBDataVar.parray);
    dataInClass->Put(L"hpqBData", 0, &hpqBDataVar, 0);
    VariantClear(&hpqBDataVar);

    //// Fill the 'InData' parameter from the 'hpqBIOSInt128' method ////

    // InData
    VARIANT inDataVar;
    VariantInit(&inDataVar);
    inDataVar.vt = VT_UNKNOWN;
    inDataVar.punkVal = dataInClass;
    methodParameters->Put(L"InData", 0, &inDataVar, 0);
    VariantClear(&inDataVar);

    //// Call the 'hpqBIOSInt128' method from the 'hpqBIntM' class ////

    hres = pSvc->ExecMethod(_bstr_t(L"hpqBIntM.InstanceName='ACPI\\PNP0C14\\0_0'"), _bstr_t(L"hpqBIOSInt128"), 0, NULL, methodParameters, NULL, &callResult);
    if (FAILED(hres)) {
        std::cerr << "Could not call method 'hpqBIOSInt128' from the class 'hpqBIntM'. Got error code = 0x" << std::hex << hres << std::endl;
        if (callResult) callResult->Release();
        // dataInClass->Release();
        methodParameters->Release();
        classObject->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    //// Get the returned data ////

    if (returnDataSize != NULL && returnData != NULL) {
        IWbemClassObject* ppResultObject = nullptr;
        callResult->GetResultObject(WBEM_INFINITE, &ppResultObject);

        // get OutData from object returned (is an object of type hpqBDataOut128)
        VARIANT outDataVar;
        VariantInit(&outDataVar);
        ppResultObject->Get(L"OutData", 0, &outDataVar, NULL, NULL);

        // get 'Data' property from the object returned
        IWbemClassObject* retData = (IWbemClassObject*)outDataVar.punkVal;
        retData->Get(L"Data", 0, &outDataVar, NULL, NULL);

        // extract the byte array from the result VARIANT
        long lower, upper;
        SAFEARRAY* safeArray = outDataVar.parray;
        SafeArrayGetLBound(safeArray, 1, &lower);
        SafeArrayGetUBound(safeArray, 1, &upper);
        long length = upper - lower + 1;
        *returnData = new BYTE[length];
        *returnDataSize = length;
        SafeArrayLock(safeArray);
        memcpy(*returnData, safeArray->pvData, length);
        SafeArrayUnlock(safeArray);

        // cleanup
        retData->Release();
        VariantClear(&outDataVar);
        ppResultObject->Release();
    }

    // cleanup
    callResult->Release();
    // dataInClass->Release();
    methodParameters->Release();
    classObject->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    return 0;
}

static void SetZoneColors(UINT zone1, UINT zone2, UINT zone3, UINT zone4) {
    // parse the `ints` -> r,g,b 1 byte each
    COLORREF colorZone1 = RGB((BYTE)(zone1 >> 0x10), (BYTE)(zone1 >> 0x8), (BYTE)(zone1));
    COLORREF colorZone2 = RGB((BYTE)(zone2 >> 0x10), (BYTE)(zone2 >> 0x8), (BYTE)(zone2));
    COLORREF colorZone3 = RGB((BYTE)(zone3 >> 0x10), (BYTE)(zone3 >> 0x8), (BYTE)(zone3));
    COLORREF colorZone4 = RGB((BYTE)(zone4 >> 0x10), (BYTE)(zone4 >> 0x8), (BYTE)(zone4));
    COLORREF zoneColors[] = { colorZone1, colorZone2, colorZone3, colorZone4 };

    int returnDataSize = 0;
    BYTE* returnData = nullptr;
    int num = Execute(131081, 2, 0, nullptr, &returnDataSize, &returnData);

    if (num == 0 && returnData != nullptr) {
        // prepare the data byte array to be sent to WMI
        for (int i = 0; i < 4; i++) {
            returnData[25 + i * 3] = GetRValue(zoneColors[i]);
            returnData[25 + i * 3 + 1] = GetGValue(zoneColors[i]);
            returnData[25 + i * 3 + 2] = GetBValue(zoneColors[i]);
        }

        // make the WMI call to set the colors
        Execute(131081, 3, returnDataSize, returnData, NULL, NULL);
        delete[] returnData;
    }
}

static bool IsLightingSupported() {
    BYTE b = 0;
    int returnDataSize = 0;
    BYTE* returnData = nullptr;
    if (Execute(131081, 1, 0, nullptr, &returnDataSize, &returnData) == 0) {
        b = (BYTE)(returnData[0] & 1u);
    }

    delete[] returnData;
    return b == 1;
}

static int GetKeyboardType() {
    int returnDataSize = 0;
    BYTE* returnData = nullptr;
    if (Execute(131080, 43, 0, nullptr, &returnDataSize, &returnData) == 0) {
        int result = returnData[0];
        delete[] returnData;
        return result;
    }

    return -1;
}

static void SetFnF4Status(bool enable) {
    BYTE array[4] = { (BYTE)(enable ? 228 : 100), 0, 0, 0 };
    Execute(131081, 5, sizeof(array), array, NULL, NULL);
}

int main(int iArgCnt, char** argv) {
    SetFnF4Status(true);
    std::cout << IsLightingSupported() << std::endl;
    std::cout << GetKeyboardType() << std::endl;

    byte r = 0; byte g = 255; byte b = 0;
    unsigned int color = (r << 0x10) | (g << 0x8) | b; // create the color
    SetZoneColors(color, color, color, color);

    return 0;
}
