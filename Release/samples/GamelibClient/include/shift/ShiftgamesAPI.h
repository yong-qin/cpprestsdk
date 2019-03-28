#pragma once
#include <string>
#include <functional>
#include "ShiftgamesParameterCode.h"
#include "ShiftgamesResultCode.h"
#ifdef SHIFTGAMES_APPSDK_CPP_EXPORTS
#define SHIFTSDKCPPWRAPPER_API __declspec(dllexport)
#else
#define SHIFTSDKCPPWRAPPER_API __declspec(dllimport)
#endif

#define SHIFTGAMES_CALLBACK_0(__selector__,__target__, ...) std::bind(&__selector__,__target__, ##__VA_ARGS__)
#define SHIFTGAMES_CALLBACK_1(__selector__,__target__, ...) std::bind(&__selector__,__target__, std::placeholders::_1, ##__VA_ARGS__)
#define SHIFTGAMES_CALLBACK_2(__selector__,__target__, ...) std::bind(&__selector__,__target__, std::placeholders::_1, std::placeholders::_2, ##__VA_ARGS__)

namespace Shiftgames {
	/// <summary>
	/// ユーザー認証情報
	/// </summary>
	/// <seealso>Shiftgames.API.ConfirmUserAuthenticationCallback</seealso>
	/// <seealso>Shiftgames.API.ConfirmUserAuthentication</seealso>
	class SHIFTSDKCPPWRAPPER_API UserAuthentication
	{
	public:
		UserAuthentication(bool succeed, std::string shiftID, std::string idToken) :_succeed(succeed), _shiftID(shiftID), _idToken(idToken) {}

		/// <summary>
		/// ユーザーのID Tokenを返す。
		/// </summary>
		/// <return>string</return>
		std::string getIDToken() const { return _idToken; }

		/// <summary>
		/// ユーザーのShift IDを返す。
		/// </summary>
		/// <return>string</return>
		std::string getShiftID() const { return _shiftID; }

		/// <summary>
		/// 認証成功可否を返す。
		/// </summary>
		/// <return>bool</return>
		bool isSucceed() const { return _succeed; }
	private:
		bool _succeed;
		std::string _shiftID;
		std::string _idToken;
	};
	/// <summary>
	/// Shift SDKのプログラミングインタフェースを定義した静的クラス。
	/// </summary>
	class SHIFTSDKCPPWRAPPER_API API {

	public:
		/// <summary>
		/// Shiftgames.API.Init実行後のコールバックを処理する関数を表す。
		/// </summary>
		/// <seealso>Shiftgames.API.Init</seealso>
		typedef std::function<void()> InitCallback;

		/// <summary>
		/// Shiftgames.API.ConfirmUserAuthentication実行後のコールバックを処理する関数を表す。
		/// </summary>
		/// <param type="const Shiftgames::UserAuthentication&amp;" name="userAuthentication">ユーザー認証情報</param>
		/// <seealso>Shiftgames.UserAuthentication</seealso>
		/// <seealso>Shiftgames.API.ConfirmUserAuthentication</seealso>
		typedef std::function<void(const UserAuthentication& userAuth)> ConfirmUserAuthenticationCallback;

		/// <summary>
		/// Shiftgames.API.RunPaymentProcess実行後のコールバックを処理する関数を表す。
		/// </summary>
		/// <param type="const std::string" name="orderID">Order ID</param>
		/// <seealso>Shiftgames.API.RunPaymentProcess</seealso>
		typedef std::function<void(const std::string orderID)> RunPaymentProcessCallback;

		// <summary>
		// Shiftgames::API::LaunchMiniGame実行後のコールバックを処理する関数を表す。
		// </summary>
		// <param type="const Shiftgames::ResultCode::MiniGameResult&amp;" name="miniGameResult">ミニゲームの結果</param>
		// <seealso>Shiftgames.ResultCode.MiniGameResult</seealso>
		typedef std::function<void(const ResultCode::MiniGameResult& result)> LaunchMiniGameCallback;

        typedef std::function<void(const std::string url)> ProtocolExecutionCallback;

		// <summary>
		// （sdk2.0.0では未支援）マクロプレイを防ぐためのミニゲームを実行する。
		// </summary>
		// <param type="const Shiftgames::ParameterCode::MiniGameType" name="type">ミニゲームの種類。必須</param>
		// <param type="const Shiftgames::API::LaunchMiniGameCallback" name="callback">コールバック関数。必須</param>
		// <seealso>Shiftgames.ParameterCode.MiniGameType</seealso>
		// <seealso>Shiftgames.API.LaunchMiniGameCallback</seealso>
		static void LaunchMiniGame(const ParameterCode::MiniGameType type, LaunchMiniGameCallback callback);

		/// <summary>
		/// 決済プロセスを開始する。
		/// </summary>
		/// <remarks>決済プロセスを開始する前にShiftgames.API.ConfirmUserAuthenticationを実行し取得したID Tokenを使用してShiftサーバー間APIからOrder IDを取得する必要がある。詳しくはExampleを参照。</remarks>
		/// <remarks>コールバック関数の引数であるOrder IDにはShiftgames.API.RunPaymentProcessのとき渡されたOrder IDが設定される。</remarks>
		/// <remarks>コールバックは決済の成功・失敗の可否と関係なく、決済プロセスが終了すると実行される。</remarks>
		/// <remarks>決済結果はShiftサーバー間APIを通じて確認できる。</remarks>
		/// <param type="const std::string" name="orderID">Shiftのサーバー間APIから取得したOrder ID。必須</param>
		/// <param type="const Shiftgames::API::RunPaymentProcessCallback&amp;" name="callback">コールバック関数。</param>
		/// <example>
		/// <code>
		/// // コールバック関数はメンバー関数とラムダ式関数どちらでも可能。ここではメンバー関数の例を示す。
		/// 
		/// #include "ShiftgamesAPI.h"
		/// 
		/// class PurchaseClass
		/// {
		///   private: std::string itemCode;
		/// 
		///   public: PurchaseClass(std::string _itemCode): itemCode(_itemCode) {}
		/// 
		///   private: void OnPaymentComplate(std::string orderID)
		///   {
		///     // デベロッパーが直接、決済結果の取得を実装
		///     DeveloperGame::PaymentStatus status = DeveloperGame::API::GetPaymentStatus(orderID);
		///     switch (status)
		///     {
		///       case DeveloperGame::PaymentStatus::Succeed:
		///         break;
		///       case DeveloperGame::PaymentStatus::Fail:
		///         break;
		///       case DeveloperGame::PaymentStatus::Cancel:
		///         break;
		///     }
		///   }
		/// 
		///   private: void OnConfirmUserAuthentication(const Shiftgames::UserAuthentication&amp; userAuth)
		///   {
		///     // デベロッパーが直接、Order IDを取得するAPIを実装
		///     std::string orderID = DeveloperGame::API::GetOrderId(purchasedItemCode, userAuth.getID Token());
		///     // Order IDをもとに決済プロセスを開始
		///     Shiftgames::API::RunPaymentProcess(orderID, SHIFTGAMES_CALLBACK_1(PurchaseClass::OnPaymentComplate, this));
		///   }
		/// 
		///   public: void Execute()
		///   {
		///     // ID TokenをもとにOrder IDを生成するため、Shiftgames::API::ConfirmUserAuthentication()を実行
		///     Shiftgames::API::ConfirmUserAuthentication(SHIFTGAMES_CALLBACK_1(PurchaseClass::OnConfirmUserAuthentication, this));
		///   }
		/// }
		/// 
		/// //実行
		/// std::string itemCode = "....";
		/// PurchaseClass* purchase = new PurchaseClass(itemCode);
		/// purchase->Execute();
		/// </code>
		/// </example>
		/// <seealso>Shiftgames.API.RunPaymentProcessCallback</seealso>
		/// <seealso>Shiftgames.API.ConfirmUserAuthentication</seealso>
		static void RunPaymentProcess(const std::string orderID, const RunPaymentProcessCallback& callback);

		/// <summary>
		/// Shiftユーザーの認証情報を取得する。認証情報はコールバック関数の引数から取得できる。
		/// </summary>
		/// <param type="const Shiftgames::API::ConfirmUserAuthenticationCallback&amp;" name="callback">コールバック関数</param>
		/// <example>
		/// <code>
		/// Shiftgames::API::ConfirmUserAuthentication( [&amp;] (const Shiftgames::UserAuthentication&amp; userAuth) {
		///   Debug::Log(userAuth.isSucceed()); // true or false
		///   Debug::Log(userAuth.getShiftID()); // shift user id
		///   Debug::Log(userAuth.getIDToken()); // token
		/// });
		/// </code>
		/// </example>
		/// <seealso>Shiftgames.API.ConfirmUserAuthenticationCallback</seealso>
		static void ConfirmUserAuthentication(const ConfirmUserAuthenticationCallback& callback);

		/// <summary>
		/// Shift SDKを初期化する。他のShift SDKのAPIを使用する前に実行する必要がある。
		/// </summary>
		/// <param type="const Shiftgames::API::InitCallback&amp;" name="callback">コールバック関数</param>
		/// <example>
		/// <code>
		/// // 1. ラムダ式関数をコールバック関数として使用する例
		/// Shiftgames::API::Init( [&amp;] () {
		///   // Init処理完了後、実行される
		/// });
		/// 
		/// // 2. メンバー関数をコールバック関数として使用する例
		/// #include "ShiftgamesAPI.h"
		/// class TestClass
		/// {
		///   private: void OnInit()
		///   {
		///      // Init処理完了後、実行される
		///   }
		///   public: void Init()
		///   {
		///     Shiftgames::API::Init(SHIFTGAMES_CALLBACK_0(TestClass::OnInit, true));
		///   }
		/// }
		/// </code>
		/// </example>
		/// <seealso>Shiftgames.API.InitCallback</seealso>
		static void Init(const InitCallback& callback);

		/// <summary>
		/// CustomUrlScheamのコールバック関数、コールバックを受信するには、SDKのInitが完了している必要がある
		/// </summary>
		/// <param type="const Shiftgames::API::ProtocolExecutionCallback&amp;" name="callback">コールバック関数</param>
		/// <example>
		/// <code>
		/// // 1. ラムダ式関数をコールバック関数として使用する例
		/// Shiftgames::API::SetProtocolExecutionCallback( [&amp;] () {
		///   // CustomUrlScheamを受信した際に実行される
		/// });
		/// 
		/// // 2. メンバー関数をコールバック関数として使用する例
		/// #include "ShiftgamesAPI.h"
		/// class TestClass
		/// {
		///   private: void OnProtocolExecution()
		///   {
		///   // CustomUrlScheamを受信した際に実行される
		///   }
		///   public: void SetProtocolExecutionCallback()
		///   {
		///     Shiftgames::API::SetProtocolExecutionCallback(SHIFTGAMES_CALLBACK_0(OnProtocolExecution、true));
		///   }
		/// }
		/// </code>
		/// </example>
		/// <seealso>Shiftgames.API.SetProtocolExecutionCallback</seealso>
		static void SetProtocolExecutionCallback(const ProtocolExecutionCallback& callback);

	private:
		API(void);
	};
}
