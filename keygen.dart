import 'dart:convert';
import 'dart:io';
import 'package:cryptography/cryptography.dart';

/// أداة سطر الأوامر لتوليد وإدارة تراخيص تطبيق إدارة عدادات المياه
/// Ed25519 License Key Generator
void main(List<String> args) async {
  final algorithm = Ed25519();

  if (args.isEmpty || args.contains('--help') || args.contains('-h')) {
    print('''
==================================================================
  Water Meter Manager - أدوات التشفير وتوليد تراخيص التفعيل
==================================================================
الاستخدام:
  1. توليد زوج مفاتيح جديد (Master KeyPair):
     dart run tool/keygen.dart --generate-keys

  2. توليد كود تفعيل لجهاز معين:
     dart run tool/keygen.dart --device "WM-A8F9-204B" --tier pro --days 365 --private-key "<BASE64_PRIVATE_KEY>"
     
  3. توليد كود تفعيل شراء كامل مدى الحياة (Lifetime):
     dart run tool/keygen.dart --device "WM-A8F9-204B" --tier lifetime --private-key "<BASE64_PRIVATE_KEY>"

الخيارات:
  --device, -d        معرف الجهاز (Device ID) المطلوب تفعيله
  --tier, -t          نوع الباقة: pro أو lifetime (الافتراضي: pro)
  --days              عدد أيام الصلاحية لباقة pro (الافتراضي: 365)
  --name, -n          اسم العميل أو المبنى (اختياري)
  --private-key, -k   المفتاح الخاص (Base64) للتوقيع
==================================================================
''');
    return;
  }

  // 1. خيار توليد زوج مفاتيح جديد
  if (args.contains('--generate-keys')) {
    final keyPair = await algorithm.newKeyPair();
    final privateKeyBytes = await keyPair.extractPrivateKeyBytes();
    final publicKey = await keyPair.extractPublicKey();

    final privateKeyB64 = base64Encode(privateKeyBytes);
    final publicKeyB64 = base64Encode(publicKey.bytes);

    print('\n🔑 تم توليد زوج مفاتيح Ed25519 جديد بنجاح:\n');
    print('==================================================================');
    print('📌 المفتاح العام (ضع هذا في كود التطبيق Public Key):');
    print(publicKeyB64);
    print('------------------------------------------------------------------');
    print('🔒 المفتاح الخاص (احفظه عندك على حاسوبك فقط ولا تشاركه أبداً):');
    print(privateKeyB64);
    print('==================================================================\n');
    return;
  }

  // 2. قراءة المعاملات لتوليد كود التفعيل
  String? deviceId;
  String tier = 'pro';
  int days = 365;
  String? customerName;
  String? privateKeyB64;

  for (int i = 0; i < args.length; i++) {
    final arg = args[i];
    if ((arg == '--device' || arg == '-d') && i + 1 < args.length) {
      deviceId = args[++i];
    } else if ((arg == '--tier' || arg == '-t') && i + 1 < args.length) {
      tier = args[++i].toLowerCase();
    } else if (arg == '--days' && i + 1 < args.length) {
      days = int.tryParse(args[++i]) ?? 365;
    } else if ((arg == '--name' || arg == '-n') && i + 1 < args.length) {
      customerName = args[++i];
    } else if ((arg == '--private-key' || arg == '-k') && i + 1 < args.length) {
      privateKeyB64 = args[++i];
    }
  }

  if (deviceId == null || deviceId.trim().isEmpty) {
    print('❌ خطأ: يرجى تحديد معرف الجهاز عبر --device "WM-XXXX-XXXX"');
    exit(1);
  }

  if (privateKeyB64 == null || privateKeyB64.trim().isEmpty) {
    print('❌ خطأ: يرجى تمرير المفتاح الخاص عبر --private-key "<KEY>"');
    exit(1);
  }

  final cleanedDevId = deviceId.replaceAll(RegExp(r'[\s\-]+'), '').toUpperCase();
  final now = DateTime.now().toUtc();
  DateTime? expiresAt;

  if (tier == 'pro') {
    expiresAt = now.add(Duration(days: days));
  }

  final payloadMap = {
    'devId': cleanedDevId,
    'tier': tier,
    'iat': now.toIso8601String(),
    if (expiresAt != null) 'exp': expiresAt.toIso8601String(),
    if (customerName != null && customerName.isNotEmpty) 'name': customerName,
  };

  final payloadJson = jsonEncode(payloadMap);
  final payloadBytes = utf8.encode(payloadJson);

  try {
    final privBytes = base64Decode(privateKeyB64.trim());
    final keyPair = await algorithm.newKeyPairFromSeed(privBytes);
    final signature = await algorithm.sign(
      payloadBytes,
      keyPair: keyPair,
    );

    final payloadB64 = base64Url.encode(payloadBytes);
    final sigB64 = base64Url.encode(signature.bytes);

    // صيغة كود التفعيل: PAYLOAD.SIGNATURE
    final fullLicenseKey = '$payloadB64.$sigB64';

    print('\n✅ تم إصدار كود التفعيل بنجاح:');
    print('==================================================================');
    print('👤 العميل: ${customerName ?? "غير محدد"}');
    print('📱 معرف الجهاز: $cleanedDevId');
    print('⭐ الباقة: ${tier == "lifetime" ? "شراء كامل مدى الحياة (Lifetime)" : "اشتراك Pro ($days يوم)"}');
    if (expiresAt != null) {
      print('📅 صالح حتى: ${expiresAt.toLocal().toString().split(".")[0]}');
    }
    print('------------------------------------------------------------------');
    print('📋 كود التفعيل للعميل (انسخ الكود بالكامل):');
    print('\n$fullLicenseKey\n');
    print('==================================================================\n');
  } catch (e) {
    print('❌ فشل في توقيع الترخيص: $e');
    exit(1);
  }
}
