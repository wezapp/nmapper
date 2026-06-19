// Charge un fichier source browser (const X = {...}) dans un contexte vm isolé.
// Les sources utilisent des globals implicites — on les injecte via `context`.
// L'astuce : on appende `this['VarName'] = VarName` au code pour exposer
// la const (accessible dans le même scope de script mais pas sur l'objet context).
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

export function loadModule(absolutePath, exportName, context = {}) {
    const code = readFileSync(absolutePath, 'utf8');
    const ctx = { ...context };
    vm.createContext(ctx);
    vm.runInContext(code + `\nthis['${exportName}'] = ${exportName};`, ctx);
    return ctx[exportName];
}
