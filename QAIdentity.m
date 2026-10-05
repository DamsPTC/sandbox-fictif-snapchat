// QAIdentity.m — instrumentation Objective-C de l'app de test.
// ARC. Frameworks : Foundation, UIKit, AdSupport, Security, CoreTelephony, DeviceCheck.
// Configuration Info.plist : QAIdentityEnabled = YES (seule clé requise).
// Option : QAIdentityIncludeSynchronizable = YES pour inclure les éléments iCloud.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AdSupport/AdSupport.h>
#import <Security/Security.h>
#import <CoreTelephony/CTTelephonyNetworkInfo.h>
#import <DeviceCheck/DeviceCheck.h>
#import <objc/runtime.h>
#import <dispatch/dispatch.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <string.h>
#import <stdlib.h>
#import <errno.h>

static NSString * const QAIDFVKey = @"QAIdentity.IDFV";
static NSString * const QAIDFAKey = @"QAIdentity.IDFA";
static NSString * const QASerialKey = @"QAIdentity.SerialNumber";
static NSString * const QAMachineUUIDKey = @"QAIdentity.MachineUUID";
static NSString * const QAKernelUUIDKey = @"QAIdentity.KernelUUID";
static NSString * const QAAttemptKey = @"QAIdentity.KeychainResetAttempted";
static NSString * const QASuccessKey = @"QAIdentity.KeychainResetSucceeded";
static NSString * const QAResultsKey = @"QAIdentity.KeychainResetResults";

// Immuables pendant le processus. Modifier les préférences puis relancer l'app.
static NSUUID *QAIDFV;
static NSUUID *QAIDFA;

static NSUUID *QALoadUUID(NSUserDefaults *defaults, NSString *key) {
    id stored = [defaults objectForKey:key];
    NSUUID *uuid = nil;
    if ([stored isKindOfClass:[NSString class]]) {
        uuid = [[NSUUID alloc] initWithUUIDString:(NSString *)stored];
    }
    if (uuid == nil) {
        uuid = [NSUUID UUID];
        [defaults setObject:uuid.UUIDString forKey:key];
    }
    return uuid;
}

static NSUUID *QAIdentifierForVendor(id self, SEL selector) {
    (void)self; (void)selector;
    return QAIDFV;
}

static NSUUID *QAAdvertisingIdentifier(id self, SEL selector) {
    (void)self; (void)selector;
    return QAIDFA;
}

static NSString *QAModel(id self, SEL selector) {
    (void)self; (void)selector;
    return @"iPhone13,1";
}

static NSString *QASystemVersion(id self, SEL selector) {
    (void)self; (void)selector;
    return @"15.1";
}

static NSString *QAName(id self, SEL selector) {
    (void)self; (void)selector;
    return @"iPhone";
}

// CTTelephonyNetworkInfo : simulateur sans SIM.
static id QASubscriberCellularProvider(id self, SEL selector) {
    (void)self; (void)selector;
    return nil;
}

static id QAServiceSubscriberCellularProviders(id self, SEL selector) {
    (void)self; (void)selector;
    return nil;
}

// DCDevice : appareil simulé sans DeviceCheck.
static BOOL QAIsSupported(id self, SEL selector) {
    (void)self; (void)selector;
    return NO;
}

static BOOL QAReplaceMethod(Class cls, SEL selector, IMP replacement) {
    Method method = class_getInstanceMethod(cls, selector);
    if (method == NULL) {
        NSLog(@"[QAIdentity] Méthode absente : %@ %@",
              NSStringFromClass(cls), NSStringFromSelector(selector));
        return NO;
    }
    if (!class_addMethod(cls, selector, replacement,
                         method_getTypeEncoding(method))) {
        method_setImplementation(method, replacement);
    }
    return YES;
}

// ---- Valeurs matérielles simulées, persistées dans NSUserDefaults ----

static char QASerial[16];
static char QAMachineUUID[40];
static char QAKernelUUID[40];
static dispatch_once_t QAValuesOnce;

static void QAEnsureSysctlValues(void) {
    dispatch_once(&QAValuesOnce, ^{
        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        NSString *serial = [defaults stringForKey:QASerialKey];
        if ([serial length] != 12) {
            static const char allowed[] = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
            char buffer[13];
            for (NSUInteger i = 0; i < 12; i++) {
                buffer[i] = allowed[arc4random_uniform((uint32_t)(sizeof(allowed) - 1))];
            }
            buffer[12] = '\0';
            serial = [NSString stringWithUTF8String:buffer];
            [defaults setObject:serial forKey:QASerialKey];
        }
        strlcpy(QASerial, serial.UTF8String, sizeof(QASerial));

        NSString *machineUUID = [defaults stringForKey:QAMachineUUIDKey];
        if ([machineUUID length] != 36) {
            machineUUID = [NSUUID UUID].UUIDString;
            [defaults setObject:machineUUID forKey:QAMachineUUIDKey];
        }
        strlcpy(QAMachineUUID, machineUUID.UTF8String, sizeof(QAMachineUUID));

        NSString *kernelUUID = [defaults stringForKey:QAKernelUUIDKey];
        if ([kernelUUID length] != 36) {
            kernelUUID = [NSUUID UUID].UUIDString;
            [defaults setObject:kernelUUID forKey:QAKernelUUIDKey];
        }
        strlcpy(QAKernelUUID, kernelUUID.UTF8String, sizeof(QAKernelUUID));
        [defaults synchronize];
    });
}

// ---- Interposition matérielle : sysctlbyname et uname ----

static const char QAMachine[] = "iPhone13,1";

static const char *QASimulatedSysctlValue(const char *name) {
    if (name == NULL) return NULL;
    if (strcmp(name, "hw.machine") == 0) return QAMachine;
    if (strcmp(name, "kern.serialnumber") == 0) { QAEnsureSysctlValues(); return QASerial; }
    if (strcmp(name, "hw.machineuuid") == 0) { QAEnsureSysctlValues(); return QAMachineUUID; }
    if (strcmp(name, "kern.uuid") == 0) { QAEnsureSysctlValues(); return QAKernelUUID; }
    return NULL;
}

static int QA_sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
                          void *newp, size_t newlen) {
    const char *value = QASimulatedSysctlValue(name);
    if (value != NULL) {
        size_t len = strlen(value) + 1;
        if (oldp == NULL) {
            if (oldlenp != NULL) *oldlenp = len;
            return 0;
        }
        if (oldlenp != NULL && *oldlenp >= len) {
            memcpy(oldp, value, len);
            *oldlenp = len;
            return 0;
        }
        if (oldlenp != NULL) *oldlenp = len;
        errno = ENOMEM;
        return -1;
    }
    return sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

static int QA_uname(struct utsname *buf) {
    int ret = uname(buf);
    if (ret == 0 && buf != NULL) {
        strlcpy(buf->machine, QAMachine, sizeof(buf->machine));
    }
    return ret;
}

// DYLD_INTERPOSE défini localement : aucune dépendance d'en-tête supplémentaire.
struct QAInterposeTuple { const void *replacement; const void *replacee; };
#define QA_INTERPOSE(replacement, replacee) \
    __attribute__((used)) static const struct QAInterposeTuple \
    QA_interpose_##replacee \
    __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)&(replacement), (const void *)&(replacee) };

QA_INTERPOSE(QA_sysctlbyname, sysctlbyname)
QA_INTERPOSE(QA_uname, uname)

// ---- Nettoyage unique par installation : keychain, Caches et tmp ----

static void QARemoveDirectoryContents(NSString *directory) {
    NSFileManager *manager = [NSFileManager defaultManager];
    BOOL isDirectory = NO;
    if (![manager fileExistsAtPath:directory isDirectory:&isDirectory] || !isDirectory) {
        return;
    }
    NSArray *entries = [manager contentsOfDirectoryAtPath:directory error:nil];
    for (NSString *entry in entries) {
        [manager removeItemAtPath:[directory stringByAppendingPathComponent:entry] error:NULL];
    }
}

static void QAResetKeychainOnce(NSUserDefaults *defaults, NSBundle *bundle) {
    if ([defaults boolForKey:QAAttemptKey]) {
        return;
    }

    BOOL includeSynchronizable = [[bundle objectForInfoDictionaryKey:
                                  @"QAIdentityIncludeSynchronizable"] boolValue];

    // Une seule tentative pour cette installation, même en cas d'erreur.
    [defaults setBool:YES forKey:QAAttemptKey];
    [defaults setBool:NO forKey:QASuccessKey];
    [defaults removeObjectForKey:QAResultsKey];
    if (![defaults synchronize]) {
        NSLog(@"[QAIdentity] Checkpoint non enregistré : nettoyage annulé.");
        return;
    }

    NSArray *classes = @[
        (__bridge id)kSecClassIdentity,
        (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecClassInternetPassword,
        (__bridge id)kSecClassKey,
        (__bridge id)kSecClassCertificate
    ];
    NSMutableDictionary *results = [NSMutableDictionary dictionary];
    BOOL succeeded = YES;

    for (id itemClass in classes) {
        NSDictionary *query = @{
            (__bridge id)kSecClass: itemClass,
            (__bridge id)kSecAttrSynchronizable: includeSynchronizable
                ? (__bridge id)kSecAttrSynchronizableAny : @NO
        };
        OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
        results[(NSString *)itemClass] = @(status);
        if (status != errSecSuccess && status != errSecItemNotFound) {
            succeeded = NO;
            NSLog(@"[QAIdentity] SecItemDelete %@ : OSStatus=%d",
                  itemClass, (int)status);
        }
    }

    [defaults setObject:results forKey:QAResultsKey];
    [defaults setBool:succeeded forKey:QASuccessKey];
    [defaults synchronize];

    // Conteneur de test : vider Caches et tmp, sans toucher aux préférences
    // (où sont stockées les valeurs simulées).
    QARemoveDirectoryContents([NSHomeDirectory() stringByAppendingPathComponent:@"Library/Caches"]);
    QARemoveDirectoryContents([NSHomeDirectory() stringByAppendingPathComponent:@"tmp"]);

    NSLog(@"[QAIdentity] Nettoyage Keychain : %@",
          succeeded ? @"terminé" : @"incomplet — voir les OSStatus");
}

__attribute__((constructor))
static void QAIdentityInitialize(void) {
    @autoreleasepool {
        NSBundle *bundle = [NSBundle mainBundle];
        // Le dylib doit être chargé uniquement dans le binaire principal.
        if ([[[bundle bundlePath] pathExtension] isEqualToString:@"appex"]) {
            return;
        }
        if (![[bundle objectForInfoDictionaryKey:@"QAIdentityEnabled"] boolValue]) {
            return;
        }

        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            Class device = [UIDevice class];
            Class ads = [ASIdentifierManager class];
            Class telephony = [CTTelephonyNetworkInfo class];
            Class dcdevice = [DCDevice class];
            if (class_getInstanceMethod(device, @selector(identifierForVendor)) == NULL ||
                class_getInstanceMethod(device, @selector(model)) == NULL ||
                class_getInstanceMethod(device, @selector(systemVersion)) == NULL ||
                class_getInstanceMethod(device, @selector(name)) == NULL ||
                class_getInstanceMethod(ads, @selector(advertisingIdentifier)) == NULL ||
                class_getInstanceMethod(telephony, @selector(subscriberCellularProvider)) == NULL ||
                class_getInstanceMethod(telephony, @selector(serviceSubscriberCellularProviders)) == NULL ||
                class_getInstanceMethod(dcdevice, @selector(isSupported)) == NULL) {
                NSLog(@"[QAIdentity] API attendue absente : initialisation annulée.");
                return;
            }

            NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
            QAIDFV = QALoadUUID(defaults, QAIDFVKey);
            QAIDFA = QALoadUUID(defaults, QAIDFAKey);
            QAEnsureSysctlValues();
            if (![defaults synchronize]) {
                NSLog(@"[QAIdentity] UUID non persistés : initialisation annulée.");
                return;
            }

            BOOL installed = YES;
            installed &= QAReplaceMethod(device, @selector(identifierForVendor),
                                         (IMP)QAIdentifierForVendor);
            installed &= QAReplaceMethod(ads, @selector(advertisingIdentifier),
                                         (IMP)QAAdvertisingIdentifier);
            installed &= QAReplaceMethod(device, @selector(model), (IMP)QAModel);
            installed &= QAReplaceMethod(device, @selector(systemVersion),
                                         (IMP)QASystemVersion);
            installed &= QAReplaceMethod(device, @selector(name), (IMP)QAName);
            installed &= QAReplaceMethod(telephony, @selector(subscriberCellularProvider),
                                         (IMP)QASubscriberCellularProvider);
            installed &= QAReplaceMethod(telephony, @selector(serviceSubscriberCellularProviders),
                                         (IMP)QAServiceSubscriberCellularProviders);
            installed &= QAReplaceMethod(dcdevice, @selector(isSupported),
                                         (IMP)QAIsSupported);
            if (!installed) {
                NSLog(@"[QAIdentity] Installation partielle : vérifier les autres hooks.");
                return;
            }

            QAResetKeychainOnce(defaults, bundle);
            NSLog(@"[QAIdentity] Simulation active : iPhone13,1 / iOS 15.1, sans SIM, sans DeviceCheck.");
        });
    }
}
