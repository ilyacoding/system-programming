#include "stdafx.h"
#include "DirectionalVector.h"

DirectionalVector::DirectionalVector()
{
	this->speed = 0;
	this->accelerate = 3;
	this->delta = 40;
	this->blow = 0.95;
	this->isPressed = false;
}

void DirectionalVector::IncreaseSpeed()
{
	speed += delta;
}

void DirectionalVector::StartKeyPress()
{
	IncreaseSpeed();
	isPressed = true;
}

void DirectionalVector::StopKeyPress()
{
	isPressed = false;
}

float DirectionalVector::Move()
{
	speed -= accelerate;
	return accelerate * speed / delta;
}

bool DirectionalVector::CanMove()
{
	return speed > 0.001;
}

bool DirectionalVector::IsPressed()
{
	return isPressed;
}

float DirectionalVector::InvertDirection()
{
	float invertedSpeed = speed;
	speed = 0;
	return invertedSpeed;
}

void DirectionalVector::ProcessBlow(float speed)
{
	speed *= blow;
	this->speed = speed;
}
