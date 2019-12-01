#!/usr/bin/env node

const fs = require('fs');

var langList = fs.readdirSync("./locales/");
var translation = {};
var translationSize = 0;

function parseI18N(lang, data, prefix) {
  Object.keys(data).forEach(objKey => {
    if ((typeof data[objKey]) === "string") {
      var trKey = (prefix?prefix+"."+objKey:objKey);
      if (translation[trKey] === undefined) {
        translation[trKey] = [lang];
      } else {
        translation[trKey].push(lang);
      }
    } else if ((typeof data[objKey]) === "object") {
      var newPrefix = (prefix?prefix+"."+objKey:objKey);
      parseI18N(lang, data[objKey], newPrefix);
    }
  });
}

langList.forEach(lang => {
  var file = "./locales/"+lang+"/translations.json"
  console.log("process file", file);
  var data;
  try {
    data = fs.readFileSync("./locales/"+lang+"/translations.json");
  } catch (e) {
    console.err("error reading file", err);
    process.exit(1);
  }
  var parsed;
  try {
    parsed = JSON.parse(data);
  } catch (e) {
    console.err("error parsing file", err);
    process.exit(1);
  }
  parseI18N(lang, parsed, false);
  translationSize++;
});

var hasError = false;
Object.keys(translation).forEach(key => {
  if (translation[key].length !== translationSize) {
    hasError = true;
    console.log("Error key", key, translation[key]);
  }
});

if (!hasError) {
  console.log("No error in files");
}
