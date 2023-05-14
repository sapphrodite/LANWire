/*  @file	sfx.h
	@brief	abstraction of sfx class and functions
*/

#ifndef AUDIO_H
#define AUDIO_H

#include <SDL/SDL.h>
#include <SDL/SDL_mixer.h>
#include <vector>

class Sound
{
public:
	// CONSTRUCTOR FOR SOUND: BOTH SFX AND MUSIC
	Sound();
	~Sound();

	//SFX
	void addSFX(const char* path);
	void playSFX(const int which) const;

	//MUSIC
	void addMusic(const char* path);
	void playMusic();
	void togglePause();

	//CLOSING FUNCTION
	void quit();

private:
	// SFX
	std::vector<Mix_Chunk*> sfxTracklist;

	// MUSIC
	std::vector<Mix_Music*> musicTracklist;
	bool isPlaying = false;
	bool isPaused = false;

};

#endif
