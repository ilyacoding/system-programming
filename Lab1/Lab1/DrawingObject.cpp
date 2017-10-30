#include "stdafx.h"
#include "DrawingObject.h"

DrawingObject::DrawingObject()
{
	this->x1 = 50;
	this->y1 = 50;
	this->x2 = 100;
	this->y2 = 100;

	Initialize();
}

DrawingObject::DrawingObject(float x1, float y1, float x2, float y2)
{
	this->x1 = x1;
	this->y1 = y1;
	this->x2 = x2;
	this->y2 = y2;

	Initialize();
}

void DrawingObject::Initialize()
{
	for (int i = LEFT; i != NONE; i++)
	{
		auto movingDirection = static_cast<MovingDirection>(i);
		directionalVectors[movingDirection] = new DirectionalVector();
	}
}

void DrawingObject::Accelerate()
{
	for (int i = LEFT; i != NONE; i++)
	{
		auto movingDirection = static_cast<MovingDirection>(i);
		if (directionalVectors[movingDirection]->IsPressed())
		{
			directionalVectors[movingDirection]->IncreaseSpeed();
		}
	}
}

void DrawingObject::DifferentDirectionProcess()
{
	while (directionalVectors[RIGHT]->CanMove() && directionalVectors[LEFT]->CanMove())
	{
		directionalVectors[RIGHT]->Move();
		directionalVectors[LEFT]->Move();
	}

	while (directionalVectors[UP]->CanMove() && directionalVectors[DOWN]->CanMove())
	{
		directionalVectors[UP]->Move();
		directionalVectors[DOWN]->Move();
	}
}

void DrawingObject::MoveLeft(float width)
{
	if (directionalVectors[LEFT]->CanMove())
	{
		float delta = directionalVectors[LEFT]->Move();

		if (x1 - delta < 0)
		{
			directionalVectors[RIGHT]->ProcessBlow(directionalVectors[LEFT]->InvertDirection());
		}
		else
		{
			x1 -= delta;
			x2 -= delta;
		}
	}
}

void DrawingObject::MoveRight(float width)
{
	if (directionalVectors[RIGHT]->CanMove())
	{
		float delta = directionalVectors[RIGHT]->Move();

		if (x2 + delta > width)
		{
			directionalVectors[LEFT]->ProcessBlow(directionalVectors[RIGHT]->InvertDirection());
		}
		else
		{
			x1 += delta;
			x2 += delta;
		}
	}
}

void DrawingObject::MoveUp(float height)
{
	if (directionalVectors[UP]->CanMove())
	{
		float delta = directionalVectors[UP]->Move();

		if (y1 - delta < 0)
		{
			directionalVectors[DOWN]->ProcessBlow(directionalVectors[UP]->InvertDirection());
		}
		else
		{
			y1 -= delta;
			y2 -= delta;
		}
	}
}

void DrawingObject::MoveDown(float height)
{
	if (directionalVectors[DOWN]->CanMove())
	{
		float delta = directionalVectors[DOWN]->Move();

		if (y2 + delta > height)
		{
			directionalVectors[UP]->ProcessBlow(directionalVectors[DOWN]->InvertDirection());
		}
		else
		{
			y1 += delta;
			y2 += delta;
		}
	}
}


void DrawingObject::Move(int height, int width)
{
	float delta;

	DifferentDirectionProcess();
	
	MoveLeft(width);
	MoveRight(width);
	MoveUp(height);
	MoveDown(height);
}

bool DrawingObject::isMoving()
{
	for (int i = LEFT; i != NONE; i++)
	{
		auto movingDirection = static_cast<MovingDirection>(i);
		if (directionalVectors[movingDirection]->CanMove())
		{
			return true;
		}
	}
	return false;
}

void DrawingObject::StartKeyPress(MovingDirection movingDirection)
{
	directionalVectors[movingDirection]->StartKeyPress();
}

void DrawingObject::StopKeyPress(MovingDirection movingDirection)
{
	directionalVectors[movingDirection]->StopKeyPress();
}

void DrawingObject::WheelScroll(MovingDirection movingDirection)
{
	directionalVectors[movingDirection]->IncreaseSpeed();
}

void DrawingObject::SetSize(float height, float width)
{
	x1 = 0;
	x2 = width;

	y1 = 0;
	y2 = height;
}
