//========= Copyright � 1996-2008, Valve LLC, All rights reserved. ============
//
// Purpose: Main class for the space war game client
//
// $NoKeywords: $
//=============================================================================

#ifndef GAMECLIENT_H
#define GAMECLIENT_H

#include "GameEngine.h"

enum EClientGameState
{
  k_EClientGameStartServer,
  k_EClientGameActive,
  k_EClientGameWaitingForPlayers,
  k_EClientGameMenu,
  k_EClientGameQuitMenu,
  k_EClientGameExiting,
  k_EClientGameInstructions,
  k_EClientGameDraw,
  k_EClientGameWinner,
  k_EClientGameConnecting,
  k_EClientGameConnectionFailure,
  k_EClientFindInternetServers,
  k_EClientStatsAchievements,
  k_EClientCreatingLobby,
  k_EClientInLobby,
  k_EClientFindLobby,
  k_EClientJoiningLobby,
  k_EClientFindLANServers,
  k_EClientRemoteStorage,
  k_EClientLeaderboards,
  k_EClientFriendsList,
  k_EClientMinidump,
  k_EClientConnectingToSteam,
  k_EClientLinkSteamAccount,
  k_EClientAutoCreateAccount,
  k_EClientRetrySteamConnection,
  k_EClientClanChatRoom,
  k_EClientWebCallback,
  k_EClientMusic,
  k_EClientWorkshop,
  k_EClientHTMLSurface,
  k_EClientInGameStore,
};

class CMainMenu;

class CGameClient
{
public:
	//Constructor
	CGameClient( IGameEngine *pEngine );

	// Shared init for all constructors
	void Init( IGameEngine *pGameEngine );

	// Destructor
	~CGameClient();

	// Run a game frame
	void RunFrame();

  // Menu callback handler (handles a bunch of menus that just change state with no extra data)
  void OnMenuSelection( EClientGameState eState ) { SetGameState( eState ); }

  // Set game state
  void SetGameState( EClientGameState eState ) { m_eGameState = eState; };
  EClientGameState GetGameState() { return m_eGameState; }

private:
	// pointer to game engine instance we are running under
	IGameEngine *m_pGameEngine;
  
  // Current game state
  EClientGameState m_eGameState;

  // Main menu instance
  CMainMenu *m_pMainMenu;

};

// Must define this stuff before BaseMenu.h as it depends on calling back into us through these accessors
extern CGameClient *g_pGameClient;
CGameClient *GameClient();

#endif // GAMECLIENT_H
