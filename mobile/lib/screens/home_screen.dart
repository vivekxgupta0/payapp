import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../providers/auth_provider.dart';
import '../providers/wallet_provider.dart';
import '../providers/transaction_provider.dart';
import '../services/sync_engine.dart';
import '../services/security/security_manager.dart';
import 'user/user_dashboard.dart';
import 'user/pay_screen.dart';
import 'user/wallet_screen.dart';
import 'user/history_screen.dart';
import 'merchant/merchant_dashboard.dart';
import 'merchant/accept_payment.dart';
import 'merchant/settlement_screen.dart';
import '../config/theme.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => HomeScreenState();
}

class HomeScreenState extends State<HomeScreen> {
  int _currentIndex = 0;

  void setTab(int index){
    setState(() => _currentIndex=index);
  }

  @override
  void initState() {
    super.initState();
    _initData();
  }

  Future<void> _initData() async {
    final auth = context.read<AuthProvider>();
    final wallet = context.read<WalletProvider>();
    final txProvider = context.read<TransactionProvider>();

    // Load cached tokens
    await wallet.loadCachedTokens();
    await wallet.checkConnectivity();

    // Load local transactions
    await txProvider.loadLocalTransactions(userId: auth.user?.id);

    // Initialize security layer (device keys, integrity check, registration)
    final secResult = await SecurityManager().initialize();
    if (!secResult.isDeviceSecure) {
      debugPrint('SECURITY: Device integrity check flagged issues');
    }

    // Start background sync (existing token-based + new blob-based)
    txProvider.startSync();
    SyncEngine().start();

    // If online, request fresh tokens
    if (wallet.isOnline) {
      if(auth.isUser){
        await wallet.requestTokens();
      }
      await txProvider.fetchServerTransactions(isUser: auth.isUser, userId: auth.user?.id);
    }
  }

  @override
  Widget build(BuildContext context) {
    final auth = context.watch<AuthProvider>();
    final isUser = auth.isUser;

    final userPages = [
      const UserDashboard(),
      const PayScreen(),
      const WalletScreen(),
      const HistoryScreen(),
    ];

    final merchantPages = [
      const MerchantDashboard(),
      const AcceptPaymentScreen(),
      const SettlementScreen(),
    ];

    final isOnline = context.watch<WalletProvider>().isOnline;

    return Scaffold(
      body: Column(
        children: [
          // ── Offline mode banner ───────────────────────────────
          AnimatedContainer(
            duration: const Duration(milliseconds: 350),
            curve: Curves.easeInOut,
            height: isOnline ? 0 : 38,
            color: const Color(0xFFE65100),
            child: isOnline
                ? const SizedBox.shrink()
                : const SafeArea(
                    bottom: false,
                    child: Center(
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Icon(Icons.wifi_off,
                              color: Colors.white, size: 14),
                          SizedBox(width: 6),
                          Text(
                            'Offline Mode  •  Payments use your offline credit limit',
                            style: TextStyle(
                              color: Colors.white,
                              fontSize: 12,
                              fontWeight: FontWeight.w600,
                              letterSpacing: 0.2,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
          ),
          Expanded(
            child: isUser
                ? userPages[_currentIndex.clamp(0, userPages.length - 1)]
                : merchantPages[
                    _currentIndex.clamp(0, merchantPages.length - 1)],
          ),
        ],
      ),
      bottomNavigationBar: Container(
        decoration: BoxDecoration(
          color: Colors.white,
          boxShadow: [
            BoxShadow(
              color: Colors.black.withOpacity(0.08),
              blurRadius: 12,
              offset: const Offset(0, -2),
            ),
          ],
        ),
        child: NavigationBar(
          selectedIndex: _currentIndex,
          onDestinationSelected: (i) => setState(() => _currentIndex = i),
          backgroundColor: Colors.white,
          elevation: 0,
          indicatorColor: AppTheme.paytmBlue.withOpacity(0.12),
          destinations: isUser
              ? const [
                  NavigationDestination(
                    icon: Icon(Icons.home_outlined),
                    selectedIcon: Icon(Icons.home, color: AppTheme.navyBlue),
                    label: 'Home',
                  ),
                  NavigationDestination(
                    icon: Icon(Icons.send_outlined),
                    selectedIcon: Icon(Icons.send, color: AppTheme.navyBlue),
                    label: 'Pay',
                  ),
                  NavigationDestination(
                    icon: Icon(Icons.account_balance_wallet_outlined),
                    selectedIcon: Icon(Icons.account_balance_wallet, color: AppTheme.navyBlue),
                    label: 'Wallet',
                  ),
                  NavigationDestination(
                    icon: Icon(Icons.history_outlined),
                    selectedIcon: Icon(Icons.history, color: AppTheme.navyBlue),
                    label: 'Passbook',
                  ),
                ]
              : const [
                  NavigationDestination(
                    icon: Icon(Icons.store_outlined),
                    selectedIcon: Icon(Icons.store, color: AppTheme.navyBlue),
                    label: 'Dashboard',
                  ),
                  NavigationDestination(
                    icon: Icon(Icons.qr_code_scanner_outlined),
                    selectedIcon: Icon(Icons.qr_code_scanner, color: AppTheme.navyBlue),
                    label: 'Accept',
                  ),
                  NavigationDestination(
                    icon: Icon(Icons.receipt_long_outlined),
                    selectedIcon: Icon(Icons.receipt_long, color: AppTheme.navyBlue),
                    label: 'Settlement',
                  ),
                ],
        ),
      ),
    );
  }
}
