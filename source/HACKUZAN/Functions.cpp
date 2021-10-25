#include "stdafx.h"
#include "Functions.h"
#include "Offsets.h"

namespace HACKUZAN {

	fnGetGameTime Functions::GetGameTime;
	fnTranslateString Functions::TranslateString;
	fnGetPing Functions::GetPing;
	fnChangerCharacterData Functions::ChangerCharacterData;
	fnIssueOrder Functions::IssueOrder;
	fnCastSpell Functions::CastSpell;
	fnGetAttackCastDelay Functions::GetAttackCastDelay;
	fnGetAttackDelay Functions::GetAttackDelay;
	fnWorldToScreen Functions::WorldToScreen;

	fnGetCell Functions::GetCell;
	fnGetHeightForPosition Functions::GetHeightForPosition;

	fnGetBasicAttack Functions::GetBasicAttack;

	fnOnProcessSpellW Functions::OnProcessSpellW;
	fnOnProcessSpell Functions::OnProcessSpell;
	fnOnFinishCast Functions::OnFinishCast;
	fnOnStopCast Functions::OnStopCast;
	fnOnPlayAnimation Functions::OnPlayAnimation;
	fnCreateObject Functions::OnCreateObject;
	fnDeleteObject Functions::OnDeleteObject;

	fnCreatePath Functions::CreatePath;

	fnIsTurret Functions::IsTurret;
	fnIsMinion Functions::IsMinion;
	fnIsHero Functions::IsHero;
	fnIsMissile Functions::IsMissile;
	fnIsTroyEnt Functions::IsTroyEnt;
	fnIsNexus Functions::IsNexus;
	fnIsInhibitor Functions::IsInhibitor;
	fnIsTargetable Functions::IsTargetable;
	fnIsAlive Functions::IsAlive;

	void Functions::Initialize() {

		GetGameTime = (fnGetGameTime)DEFINE_RVA(Offsets::ClockFacade::GetGameTime);
		GetPing = (fnGetPing)DEFINE_RVA(Offsets::NetClient::GetPing);
		//CastSpell = (fnCastSpell)DEFINE_RVA(Offsets::Functions::CastSpell);
		GetAttackCastDelay = (fnGetAttackCastDelay)DEFINE_RVA(Offsets::Functions::GetAttackCastDelay);
		GetAttackDelay = (fnGetAttackDelay)DEFINE_RVA(Offsets::Functions::GetAttackDelay);
		WorldToScreen = (fnWorldToScreen)DEFINE_RVA(Offsets::RenderLayer::WorldToScreen);

		//CreatePath = (fnCreatePath)DEFINE_RVA(Offsets::AIManagerClient::CreatePath);

	//	GetCell = (fnGetCell)DEFINE_RVA(Offsets::NavGrid::GetCell);
	//	GetHeightForPosition = (fnGetHeightForPosition)DEFINE_RVA(Offsets::NavGrid::GetHeightForPosition);

		IsTargetable = (fnIsTargetable)DEFINE_RVA(Offsets::ManagerTemplate::oIsTargetable);
		IsAlive = (fnIsAlive)DEFINE_RVA(Offsets::ManagerTemplate::oIsAlive);
		IsMinion = (fnIsMinion)DEFINE_RVA(Offsets::ManagerTemplate::oIsMinion);
		IsTurret = (fnIsTurret)DEFINE_RVA(Offsets::ManagerTemplate::oIsTurret);
		IsHero = (fnIsHero)DEFINE_RVA(Offsets::ManagerTemplate::oIsHero);
		IsMissile = (fnIsMissile)DEFINE_RVA(Offsets::ManagerTemplate::oIsMissile);
		IsNexus = (fnIsNexus)DEFINE_RVA(Offsets::ManagerTemplate::oIsNexus);
		IsInhibitor = (fnIsInhibitor)DEFINE_RVA(Offsets::ManagerTemplate::oIsInhib);
		IsTroyEnt = (fnIsTroyEnt)DEFINE_RVA(Offsets::ManagerTemplate::oIsTroy);
	}
}