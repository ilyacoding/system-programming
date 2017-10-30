#pragma once
#include "DirectionalVector.h"
#include <vector>

enum MovingDirection
{
	LEFT, RIGHT, UP, DOWN, NONE
};

class DrawingObject
{
	private:
		void Initialize();
		void DifferentDirectionProcess();
		void MoveLeft(float width);
		void MoveRight(float width);
		void MoveUp(float height);
		void MoveDown(float height);
	public:
		float x1, y1, x2, y2;
		DirectionalVector* directionalVectors[4];

		DrawingObject();
		DrawingObject(float, float, float, float);

		void Move(int, int);
		
		void Accelerate();
		void StartKeyPress(MovingDirection);
		void StopKeyPress(MovingDirection);
		void WheelScroll(MovingDirection);
		bool isMoving();
	
		void SetSize(float height, float width);
};
