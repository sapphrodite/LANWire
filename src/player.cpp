/*  @file	sfx.cpp
	@brief	manages creation of sound effects (sfx)
			and its functions
*/

#include <iostream>
#include "player.h"

using namespace std;

// BOTH 
Sound::Sound()
{
	//initialize sound
	SDL_Init(SDL_INIT_AUDIO);

	int rate = 22050;
	Uint16 format = AUDIO_S16SYS;
	int channels = 2;
	int buffers = 4096;

	if (Mix_OpenAudio(rate, format, channels, buffers) != 0)
	{
		std::cerr << "Audio Initialization Failed: " << Mix_GetError() << std::endl;
		exit(-1);
	}

}
Sound::~Sound()
{
	SDL_Quit();
}

// SFX
void Sound::addSFX(const char* filepath)
{
	Mix_Chunk* tmpChunk = Mix_LoadWAV(filepath);
	if (tmpChunk != nullptr)
	{
		sfxTracklist.push_back(tmpChunk);
		std::cout << "SFX #" << (sfxTracklist.size() - 1)
			<< " Loaded: " << filepath << "\n";
	}	// successfully adds to sound bank
	else
	{
		std::cerr << "Load Failed: " << Mix_GetError() << std::endl;
	}
}
void Sound::playSFX(const int which) const
{
	if (which > sfxTracklist.size() - 1)
	{
		std::cout << "Out of Range!\n";
		return;
	}
	Mix_PlayChannel(-1, sfxTracklist[which], 0);

	std::cout << "SFX: " << which << "\n";
}

// MUSIC
void Sound::addMusic(const char* filepath)
{
	Mix_Music* tmpMusic = Mix_LoadMUS(filepath);
	if (tmpMusic != nullptr)
	{
		musicTracklist.push_back(tmpMusic);
		std::cout << "MUSIC #" << (musicTracklist.size() - 1)
			<< " Loaded: " << filepath << "\n";
	}
	else
	{
		std::cerr << "Load Failed: " << Mix_GetError() << std::endl;
	}
}
void Sound::playMusic()
{
	if (musicTracklist.empty())
		return;
	
	
	Mix_PlayMusic(musicTracklist.back(), 0);
	isPlaying = true;
}
void Sound::togglePause()
{
	if (isPlaying && !isPaused)
	{
		Mix_PauseMusic();
		std::cout << "MUSIC PAUSED\n" << endl;
		isPaused = true;
	}
	else if (isPlaying && isPaused)
	{
		Mix_ResumeMusic();
		std::cout << "MUSIC RESUMED\n" << endl;
		isPaused = false;
	}
	else
	{
		return;
	}
}

// CLOSING FUNCTION
void Sound::quit()
{
	Mix_Quit();
}
