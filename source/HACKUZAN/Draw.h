#ifndef _DRAW_H_
#define _DRAW_H_
#pragma comment(lib, "d3dx9.lib")

#include "stdafx.h"

#include <d3d9.h>
#include <d3dx9.h>

#include "imgui.h"
#include "Vector3.h"
#include "Offsets.h"


namespace HACKUZAN {
	class GameObject;

	enum circle_type { full, half, quarter };
	enum text_alignment { lefted, centered, righted };

#define MAX_FONTS 6

	struct vertex
	{
		FLOAT x, y, z, rhw;
		DWORD color;
	};

	class Render_struct
	{
	public:
		char pad_0000[16]; //0x0000
		int32_t screenResolutionX; //0x0010
		int32_t screenResolutionY; //0x0014
		char pad_0018[80]; //0x0018
		D3DMATRIX viewMatrix; //0x0060
		D3DMATRIX projMatrix; //0x00A0
		char pad_00E8[4048]; //0x00E8
	}; //Size: 0x10B8
	static_assert(sizeof(Render_struct) == 0x10B8);


	class CDraw
	{
	public:
		CDraw()
		{
			g_pVB = NULL;
			g_pIB = NULL;
		}

		struct sScreen
		{
			int Width;
			int Height;
			int x_center;
			int y_center;
		}	Screen;

		void SetScreenInfo()
		{
			DWORD pRender = *(DWORD*)(baseAddr + (DWORD)Offsets::RenderLayer::Instance);
			Render_struct* render = (Render_struct*)(pRender);
			this->Screen.Width = render->screenResolutionX;
			this->Screen.Height = render->screenResolutionY;
			this->Screen.x_center = this->Screen.Width / 2;
			this->Screen.y_center = this->Screen.Height / 2;
		}

		ID3DXFont* pFont[MAX_FONTS];

		// GAME FUNCTION
		void RangeCircle(Vector3 position, float range, D3DCOLOR color, int a4, float a5, int a6, float alpha);
		void RangeCircle(Vector3 position, float range, D3DCOLOR color, float alpha);
		void RangeCircle(Vector3 position, float range, ImColor color, float alpha);

		bool WorldToScreen(Vector3 world, Vector3* screen);
		D3DXVECTOR2 WorldToScreen3(Vector3 pos);

		void Sprite(LPDIRECT3DTEXTURE9 tex, float x, float y, float resolution, float scale, float rotation);

		//=============================================================================================
		void Line(float x1, float y1, float x2, float y2, float width, bool antialias, DWORD color);
		void Line(Vector3 source, Vector3 dest, float gameWidth, DWORD color);

		void Box(float x, float y, float w, float h, float linewidth, DWORD color);
		void BoxFilled(float x, float y, float w, float h, DWORD color);
		void BoxBordered(float x, float y, float w, float h, float border_width, DWORD color, DWORD color_border);
		void BoxRounded(float x, float y, float w, float h, float radius, bool smoothing, DWORD color, DWORD bcolor);

		void DrawCircle(int X, int Y, int radius, int numSides, DWORD Color);
		void DrawCircle3D(Vector3 vPos, float flPoints, float flRadius, D3DCOLOR clrColor, float flThickness = 3.f);

		void Circle(float x, float y, float radius, int rotate, float circumferenceRatio, bool smoothing, int resolution, DWORD color);
		void Circle(float x, float y, float radius, int rotate, int type, bool smoothing, int resolution, DWORD color);
		void Circle(Vector3 pos, float gameRadius, D3DCOLOR);
		void CircleFilled(float x, float y, float rad, float rotate, float circumferenceRatio, int resolution, DWORD color);
		void CircleFilled(float x, float y, float rad, float rotate, int type, int resolution, DWORD color);
		void CircleFilled(Vector3 pos, float gameRadius, D3DCOLOR);

		void Text(const char* text, float x, float y, text_alignment alignment, int font, bool bordered, DWORD color, DWORD bcolor = 0);
		/*template<typename... Args>
		void TextArg(const char *text, float x, float y, text_alignment alignment, int font, bool bordered, DWORD color, DWORD bcolor = 0, Args ...);*/

		template<typename... Args>
		void TextArg(const char* text, Vector3 worldPosition, text_alignment alignment, int font, bool bordered, DWORD color, DWORD bcolor = 0, Args ...);
		void Text(const char* text, Vector3 worldPosition, text_alignment alignment, int font, bool bordered, DWORD color, DWORD bcolor = 0);


		//void Message(char *text, float x, float y, int font, int orientation);
		//void Message(int fontId, unsigned int x, unsigned int y, D3DCOLOR color, LPCSTR Message);
		//=============================================================================================

		//=============================================================================================
		int FirstFontIndex();
		void AddFont(const char* caption, float size, bool bold, bool italic);
		void FontRelease();
		void OnLostDevice();
		void OnResetDevice();
		//=============================================================================================

		void CaptureDevice(IDirect3DDevice9* device) {
			getDevice = device;
		}

		LPDIRECT3DDEVICE9 GetDevice() {
			if (!pDevice) {
				pDevice = getDevice;
			}
			return pDevice;
		}
		void SetDevice(LPDIRECT3DDEVICE9 device) { pDevice = device; }

		void Reset();
		int mFontSize;
	private:
		IDirect3DDevice9* getDevice;
		LPDIRECT3DDEVICE9 pDevice;
		LPDIRECT3DVERTEXBUFFER9 g_pVB;    // Buffer to hold vertices
		LPDIRECT3DINDEXBUFFER9  g_pIB;    // Buffer to hold indices

		static LPD3DXLINE sLine;

		LPD3DXSPRITE sSprite;
	};

	extern CDraw Draw;

	template<typename ...Args>
	inline void CDraw::TextArg(const char* text, Vector3 worldPosition, text_alignment alignment, int font, bool bordered, DWORD color, DWORD bcolor, Args ... args)
	{
		char messageBuffer[100];
		sprintf(messageBuffer, text, args...);
		this->Text(messageBuffer, worldPosition, alignment, font, bordered, color, bcolor);
	}

#endif /* _DRAW_H_ */

	//template<typename ...Args>
	//inline void CDraw::TextArg(const char * text, float x, float y, text_alignment alignment, int font, bool bordered, DWORD color, DWORD bcolor, Args ... args)
	//{
	//	char messageBuffer[100];
	//	sprintf(messageBuffer, text, args...);
	//	this->Text(messageBuffer, x, y, alignment, font, bordered, color, bcolor);
	//}



}