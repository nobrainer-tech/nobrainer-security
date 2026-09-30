#!/usr/bin/env node
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import kleur from 'kleur';

const configPath = join(homedir(), '.config', 'weather-cli', 'config.json');
const city = existsSync(configPath) ? JSON.parse(readFileSync(configPath, 'utf8')).city : 'Warsaw';

const search = 'https://geocoding-api.open-meteo.com/v1/search?count=1&name=' + encodeURIComponent(city);
const place = (await (await fetch(search)).json()).results?.[0];
if (!place) {
  console.error('City not found: ' + city);
  process.exit(1);
}

const forecast = 'https://api.open-meteo.com/v1/forecast?current=temperature_2m'
  + '&latitude=' + place.latitude + '&longitude=' + place.longitude;
const weather = await (await fetch(forecast)).json();
console.log(kleur.bold(place.name) + ': ' + weather.current.temperature_2m + ' C');
