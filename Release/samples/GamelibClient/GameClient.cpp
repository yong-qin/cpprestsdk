//========= Copyright � 1996-2008, Valve LLC, All rights reserved. ============
//
// Purpose: Main class for the space war game client
//
// $NoKeywords: $
//=============================================================================

#include "stdafx.h"
#include "GameClient.h"
#include "MainMenu.h"
#include "stdlib.h"
#include "time.h"
#ifdef WIN32
#include <direct.h>
#else
#define MAX_PATH PATH_MAX
#include <unistd.h>
#define _getcwd getcwd
#endif

CGameClient *g_pGameClient = NULL;
CGameClient* GameClient() { return g_pGameClient; }

#if defined(WIN32)
#define atoll _atoi64
#endif

extern int GetAllItems();
#ifdef WIN32
extern int ShiftPurchaseFlow();
#endif
extern int SteamPurchaseFlow();

//-----------------------------------------------------------------------------
// Purpose: Constructor
//-----------------------------------------------------------------------------
CGameClient::CGameClient( IGameEngine *pGameEngine )
{
	Init( pGameEngine );
}

//-----------------------------------------------------------------------------
// Purpose: initialize our client for use
//-----------------------------------------------------------------------------
void CGameClient::Init( IGameEngine *pGameEngine )
{
   m_eGameState = k_EClientGameMenu;
#ifdef _PS3
  else
  {
    m_eGameState = k_EClientConnectingToSteam;
    SteamUser()->LogOn( true );
  }
#endif

  g_pGameClient = this;
	m_pGameEngine = pGameEngine;
  
  // Initialize main menu
  m_pMainMenu = new CMainMenu( pGameEngine );

	// Seed random num generator
	srand( (uint32)time( NULL ) );

}

//-----------------------------------------------------------------------------
// Purpose: Destructor
//-----------------------------------------------------------------------------
CGameClient::~CGameClient()
{
  if ( m_pMainMenu )
    delete m_pMainMenu;
}

//-----------------------------------------------------------------------------
// Purpose: Main frame function, updates the state of the world and performs rendering
//-----------------------------------------------------------------------------
void CGameClient::RunFrame()
{
  // Check if escape has been pressed, we'll use that info in a couple places below
  bool bEscapePressed = false;
  if ( m_pGameEngine->BIsKeyDown( VK_ESCAPE ) ||
      m_pGameEngine->BIsControllerActionActive( eControllerDigitalAction_PauseMenu ) )
  {
    static uint64 m_ulLastESCKeyTick = 0;
    uint64 ulCurrentTickCount = m_pGameEngine->GetGameTickCount();
    if ( ulCurrentTickCount - 250 > m_ulLastESCKeyTick )
    {
      m_ulLastESCKeyTick = ulCurrentTickCount;
      bEscapePressed = true;
    }
  }
  
  // Run Steam client callbacks
  SteamAPI_RunCallbacks();
  
  // Update state for everything
  switch ( m_eGameState )
  {
    case k_EClientGameMenu:
      //m_pStarField->Render();
      m_pMainMenu->RunFrame();
      // Make sure the Steam Controller is in the correct mode.
      m_pGameEngine->SetSteamControllerActionSet( eControllerActionSet_MenuControls );
      break;
    case k_EClientInGameStoreGetAllItems:
      GetAllItems();
      SetGameState(k_EClientGameMenu);
      break;
    case k_EClientInGameStoreSteam:
      SteamPurchaseFlow();
      SetGameState(k_EClientGameMenu);
      break;
    case k_EClientInGameStoreShift:
      ShiftPurchaseFlow();
      SetGameState(k_EClientGameMenu);
      break;
    case k_EClientGameExiting:
      m_pGameEngine->Shutdown();
      return;

  }
}

