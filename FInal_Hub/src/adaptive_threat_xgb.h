/* ============================================================
 * TinyML-Based Adaptive Security Framework
 * FINAL 4-CLASS XGBOOST EMBEDDED MODEL
 * ============================================================
 * Classes:
 *   0 = NORMAL
 *   1 = LOW
 *   2 = MEDIUM
 *   3 = HIGH
 *
 * Embedded score() compatibility:
 *   output[0] = P(NORMAL)
 *   output[1] = weighted threat score
 *
 * Weighted threat score:
 *   NORMAL = 0.0
 *   LOW    = 1/3
 *   MEDIUM = 2/3
 *   HIGH   = 1.0
 *
 * Security policy:
 *   < 0.25 -> NORMAL   -> AES-128-GCM
 *   < 0.75 -> ELEVATED -> AES-256-GCM
 *   >=0.75 -> CRITICAL -> AES-256-GCM + ML-KEM-512
 * ============================================================
 */

#ifndef ADAPTIVE_THREAT_XGB_H
#define ADAPTIVE_THREAT_XGB_H

#include <math.h>
#include <stdint.h>

// ============================================================
// FEATURE ORDER
// ============================================================
// 0: rssi_mean
// 1: rssi_variance
// 2: rssi_min
// 3: rssi_max
// 4: rssi_range
// 5: packet_loss
// 6: iat_mean
// 7: iat_variance
// 8: iat_min
// 9: iat_max
// 10: packet_rate
// 11: invalid_packets

// ============================================================
// SECURITY POLICY BOUNDARIES
// ============================================================
#define THREAT_LOW 0.25f
#define THREAT_HIGH 0.75f

enum ThreatLevel
{
    THREAT_NORMAL = 0,
    THREAT_ELEVATED = 1,
    THREAT_CRITICAL = 2
};

// ============================================================
// M2CGEN FOUR-CLASS XGBOOST MODEL
// ============================================================

#include <string.h>
void softmax(double *x, int size, double *result) {
    double max = x[0];
    for (int i = 1; i < size; ++i) {
        if (x[i] > max)
            max = x[i];
    }
    double sum = 0.0;
    for (int i = 0; i < size; ++i) {
        result[i] = exp(x[i] - max);
        sum += result[i];
    }
    for (int i = 0; i < size; ++i)
        result[i] /= sum;
}
void xgb4class_raw_score(double * input, double * output) {
    double var0[4];
    double var1;
    if (input[5] >= 0.0049505) {
        if (input[10] >= 9.865349) {
            var1 = -0.007692308;
        } else {
            var1 = -0.032959327;
        }
    } else {
        var1 = 0.096923076;
    }
    double var2;
    if (input[5] >= 0.0049505) {
        if (input[0] >= -58.78) {
            var2 = -0.032605585;
        } else {
            var2 = -0.007194556;
        }
    } else {
        var2 = 0.088344164;
    }
    double var3;
    if (input[6] >= 100.50505) {
        if (input[6] >= 102.53556) {
            var3 = -0.03224774;
        } else {
            var3 = -0.0022018363;
        }
    } else {
        var3 = 0.08109362;
    }
    double var4;
    if (input[5] >= 0.0049505) {
        if (input[0] >= -58.78) {
            var4 = -0.031886082;
        } else {
            var4 = -0.0063331886;
        }
    } else {
        var4 = 0.07534436;
    }
    double var5;
    if (input[5] >= 0.0049505) {
        if (input[5] >= 0.0147545) {
            var5 = -0.03157838;
        } else {
            var5 = -0.0060377847;
        }
    } else {
        var5 = 0.07012432;
    }
    double var6;
    if (input[5] >= 0.0049505) {
        var6 = -0.031276632;
    } else {
        var6 = 0.06585006;
    }
    double var7;
    if (input[5] >= 0.0049505) {
        if (input[0] >= -58.78) {
            var7 = -0.03095003;
        } else {
            var7 = -0.004695134;
        }
    } else {
        var7 = 0.061925482;
    }
    double var8;
    if (input[5] >= 0.0049505) {
        if (input[0] >= -58.905) {
            var8 = -0.03063905;
        } else {
            var8 = -0.0045091584;
        }
    } else {
        var8 = 0.058749568;
    }
    double var9;
    if (input[5] >= 0.0049505) {
        var9 = -0.030387834;
    } else {
        var9 = 0.055853523;
    }
    double var10;
    if (input[5] >= 0.0049505) {
        if (input[10] >= 9.865349) {
            var10 = -0.0057726232;
        } else {
            var10 = -0.030108353;
        }
    } else {
        var10 = 0.053039134;
    }
    double var11;
    if (input[5] >= 0.0049505) {
        if (input[5] >= 0.024367) {
            var11 = -0.02982828;
        } else {
            var11 = -0.0052072043;
        }
    } else {
        var11 = 0.051078554;
    }
    double var12;
    if (input[5] >= 0.0049505) {
        if (input[3] >= -48.0) {
            var12 = -0.029594917;
        } else {
            var12 = -0.003668032;
        }
    } else {
        var12 = 0.04889946;
    }
    double var13;
    if (input[5] >= 0.0049505) {
        if (input[0] >= -58.574997) {
            var13 = -0.029332919;
        } else {
            var13 = -0.0040234183;
        }
    } else {
        var13 = 0.04701208;
    }
    double var14;
    if (input[5] >= 0.0049505) {
        if (input[10] >= 9.865349) {
            var14 = -0.0038642136;
        } else {
            var14 = -0.02912403;
        }
    } else {
        var14 = 0.045445185;
    }
    double var15;
    if (input[5] >= 0.0049505) {
        if (input[0] >= -58.525) {
            var15 = -0.028895209;
        } else {
            var15 = -0.0048532486;
        }
    } else {
        var15 = 0.043822575;
    }
    double var16;
    if (input[5] >= 0.0049505) {
        var16 = -0.028730962;
    } else {
        var16 = 0.042458776;
    }
    double var17;
    if (input[5] >= 0.0049505) {
        if (input[10] >= 9.776606) {
            var17 = -0.004507777;
        } else {
            var17 = -0.028453594;
        }
    } else {
        var17 = 0.04130486;
    }
    double var18;
    if (input[5] >= 0.0147545) {
        var18 = -0.028294323;
    } else {
        if (input[3] >= -46.0) {
            var18 = 0.011785128;
        } else {
            var18 = 0.04081758;
        }
    }
    double var19;
    if (input[5] >= 0.0049505) {
        if (input[0] >= -58.65) {
            var19 = -0.028126428;
        } else {
            var19 = -0.0031464936;
        }
    } else {
        var19 = 0.039158557;
    }
    double var20;
    if (input[5] >= 0.0147545) {
        var20 = -0.027925977;
    } else {
        if (input[0] >= -56.489998) {
            var20 = 0.01695903;
        } else {
            var20 = 0.03876943;
        }
    }
    double var21;
    if (input[10] >= 9.887299) {
        if (input[0] >= -55.775) {
            var21 = 0.016519044;
        } else {
            var21 = 0.03788073;
        }
    } else {
        if (input[6] >= 102.53556) {
            var21 = -0.027714083;
        } else {
            var21 = 0.0014578332;
        }
    }
    double var22;
    if (input[5] >= 0.0147545) {
        var22 = -0.027561242;
    } else {
        if (input[0] >= -56.614998) {
            var22 = 0.013751454;
        } else {
            var22 = 0.037076753;
        }
    }
    double var23;
    if (input[6] >= 101.51515) {
        if (input[10] >= 6.6284904) {
            var23 = -0.027397042;
        } else {
            var23 = -0.008389439;
        }
    } else {
        if (input[0] >= -56.489998) {
            var23 = 0.008745204;
        } else {
            var23 = 0.03630825;
        }
    }
    double var24;
    if (input[5] >= 0.0049505) {
        var24 = -0.027298067;
    } else {
        var24 = 0.035048146;
    }
    double var25;
    if (input[5] >= 0.0147545) {
        var25 = -0.027078373;
    } else {
        if (input[3] >= -46.0) {
            var25 = 0.0085478285;
        } else {
            var25 = 0.03511214;
        }
    }
    double var26;
    if (input[5] >= 0.0049505) {
        var26 = -0.02701503;
    } else {
        var26 = 0.033702567;
    }
    double var27;
    if (input[5] >= 0.0049505) {
        var27 = -0.026839051;
    } else {
        var27 = 0.033198338;
    }
    double var28;
    if (input[10] >= 9.887299) {
        if (input[0] >= -56.855) {
            var28 = 0.01039711;
        } else {
            var28 = 0.03338486;
        }
    } else {
        if (input[10] >= 9.736153) {
            var28 = -0.010837949;
        } else {
            var28 = -0.026652211;
        }
    }
    double var29;
    if (input[5] >= 0.0147545) {
        var29 = -0.02649605;
    } else {
        if (input[3] >= -46.0) {
            var29 = 0.0078030475;
        } else {
            var29 = 0.03302457;
        }
    }
    double var30;
    if (input[5] >= 0.0147545) {
        var30 = -0.026354253;
    } else {
        if (input[3] >= -46.0) {
            var30 = 0.0070010223;
        } else {
            var30 = 0.03255851;
        }
    }
    double var31;
    if (input[5] >= 0.0147545) {
        var31 = -0.026257357;
    } else {
        if (input[3] >= -46.0) {
            var31 = 0.007070541;
        } else {
            var31 = 0.032135602;
        }
    }
    double var32;
    if (input[5] >= 0.0147545) {
        var32 = -0.026125206;
    } else {
        if (input[0] >= -56.57) {
            var32 = 0.0026459822;
        } else {
            var32 = 0.03158477;
        }
    }
    double var33;
    if (input[5] >= 0.0049505) {
        var33 = -0.02613248;
    } else {
        var33 = 0.030514264;
    }
    double var34;
    if (input[6] >= 100.50505) {
        if (input[10] >= 6.693664) {
            var34 = -0.025945146;
        } else {
            var34 = -0.0088149225;
        }
    } else {
        var34 = 0.029960776;
    }
    double var35;
    if (input[6] >= 102.53556) {
        var35 = -0.025777653;
    } else {
        if (input[3] >= -46.0) {
            var35 = 0.005414234;
        } else {
            var35 = 0.030369962;
        }
    }
    double var36;
    if (input[5] >= 0.0147545) {
        var36 = -0.025647987;
    } else {
        if (input[3] >= -46.0) {
            var36 = 0.007623223;
        } else {
            var36 = 0.030414237;
        }
    }
    double var37;
    if (input[5] >= 0.0147545) {
        var37 = -0.025558785;
    } else {
        if (input[0] >= -56.489998) {
            var37 = 0.010260691;
        } else {
            var37 = 0.029976863;
        }
    }
    double var38;
    if (input[5] >= 0.0147545) {
        var38 = -0.025456581;
    } else {
        if (input[10] >= 9.96216) {
            var38 = 0.029703094;
        } else {
            var38 = 0.013091934;
        }
    }
    double var39;
    if (input[10] >= 9.887299) {
        if (input[0] >= -56.714996) {
            var39 = 0.00822239;
        } else {
            var39 = 0.029416487;
        }
    } else {
        var39 = -0.024780458;
    }
    double var40;
    if (input[5] >= 0.0147545) {
        var40 = -0.025237722;
    } else {
        if (input[3] >= -46.0) {
            var40 = 0.004055731;
        } else {
            var40 = 0.029309308;
        }
    }
    double var41;
    if (input[5] >= 0.0147545) {
        var41 = -0.025124256;
    } else {
        if (input[0] >= -56.489998) {
            var41 = 0.008946295;
        } else {
            var41 = 0.02892435;
        }
    }
    double var42;
    if (input[5] >= 0.0147545) {
        var42 = -0.025070002;
    } else {
        if (input[0] >= -56.57) {
            var42 = 0.006742511;
        } else {
            var42 = 0.02867539;
        }
    }
    double var43;
    if (input[5] >= 0.0147545) {
        var43 = -0.024949333;
    } else {
        if (input[0] >= -56.489998) {
            var43 = 0.010654717;
        } else {
            var43 = 0.02846235;
        }
    }
    double var44;
    if (input[5] >= 0.0147545) {
        var44 = -0.024860002;
    } else {
        if (input[0] >= -56.71) {
            var44 = 0.0062099486;
        } else {
            var44 = 0.028234366;
        }
    }
    double var45;
    if (input[10] >= 9.887299) {
        if (input[0] >= -57.11) {
            var45 = 0.007392367;
        } else {
            var45 = 0.028020335;
        }
    } else {
        var45 = -0.024128363;
    }
    double var46;
    if (input[5] >= 0.0147545) {
        var46 = -0.02464979;
    } else {
        if (input[0] >= -56.714996) {
            var46 = 0.0061302674;
        } else {
            var46 = 0.027838593;
        }
    }
    double var47;
    if (input[5] >= 0.0147545) {
        var47 = -0.024607312;
    } else {
        if (input[3] >= -46.0) {
            var47 = 0.0013916496;
        } else {
            var47 = 0.027772529;
        }
    }
    double var48;
    if (input[5] >= 0.0147545) {
        var48 = -0.024476508;
    } else {
        if (input[0] >= -56.489998) {
            var48 = 0.0088081295;
        } else {
            var48 = 0.027515216;
        }
    }
    double var49;
    if (input[5] >= 0.0147545) {
        var49 = -0.024415977;
    } else {
        if (input[0] >= -56.57) {
            var49 = 0.005106777;
        } else {
            var49 = 0.027295351;
        }
    }
    double var50;
    if (input[5] >= 0.0147545) {
        var50 = -0.024314482;
    } else {
        if (input[0] >= -56.57) {
            var50 = 0.004886666;
        } else {
            var50 = 0.027145589;
        }
    }
    double var51;
    if (input[5] >= 0.0049505) {
        var51 = -0.024382824;
    } else {
        var51 = 0.026016766;
    }
    double var52;
    if (input[5] >= 0.0147545) {
        var52 = -0.024064902;
    } else {
        if (input[10] >= 9.96216) {
            var52 = 0.026789827;
        } else {
            var52 = 0.008318548;
        }
    }
    double var53;
    if (input[10] >= 9.887299) {
        if (input[0] >= -57.075) {
            var53 = 0.0075081154;
        } else {
            var53 = 0.026596237;
        }
    } else {
        if (input[7] >= 433.6292) {
            var53 = -0.02370092;
        } else {
            var53 = -0.0078183105;
        }
    }
    double var54;
    if (input[5] >= 0.0049505) {
        var54 = -0.024117393;
    } else {
        var54 = 0.025275845;
    }
    double var55;
    if (input[6] >= 102.53556) {
        var55 = -0.023796774;
    } else {
        if (input[0] >= -56.885002) {
            var55 = 0.0032193647;
        } else {
            var55 = 0.02591004;
        }
    }
    double var56;
    if (input[10] >= 9.887299) {
        if (input[10] >= 9.96216) {
            var56 = 0.026138922;
        } else {
            var56 = 0.00736371;
        }
    } else {
        if (input[6] >= 104.545456) {
            var56 = -0.023357091;
        } else {
            var56 = -0.009200118;
        }
    }
    double var57;
    if (input[5] >= 0.0049505) {
        var57 = -0.02382037;
    } else {
        var57 = 0.024659267;
    }
    double var58;
    if (input[5] >= 0.0147545) {
        var58 = -0.023453914;
    } else {
        if (input[10] >= 9.957216) {
            var58 = 0.025884474;
        } else {
            var58 = 0.008435654;
        }
    }
    double var59;
    if (input[5] >= 0.0147545) {
        var59 = -0.02332071;
    } else {
        if (input[0] >= -56.855) {
            var59 = 0.0036343813;
        } else {
            var59 = 0.025747998;
        }
    }
    double var60;
    if (input[5] >= 0.0049505) {
        var60 = -0.023398152;
    } else {
        var60 = 0.024539446;
    }
    double var61;
    if (input[10] >= 9.887299) {
        var61 = 0.023984587;
    } else {
        var61 = -0.023294756;
    }
    double var62;
    if (input[5] >= 0.0147545) {
        var62 = -0.02312034;
    } else {
        if (input[0] >= -57.21) {
            var62 = 0.0064430647;
        } else {
            var62 = 0.025331995;
        }
    }
    double var63;
    if (input[5] >= 0.0147545) {
        var63 = -0.022977173;
    } else {
        if (input[0] >= -57.21) {
            var63 = 0.0035514974;
        } else {
            var63 = 0.025170816;
        }
    }
    double var64;
    if (input[6] >= 100.50505) {
        var64 = -0.021678563;
    } else {
        var64 = 0.023734642;
    }
    double var65;
    if (input[6] >= 102.53556) {
        var65 = -0.02279885;
    } else {
        if (input[3] >= -47.0) {
            var65 = 0.0073308283;
        } else {
            var65 = 0.025000116;
        }
    }
    double var66;
    if (input[5] >= 0.0147545) {
        var66 = -0.022598956;
    } else {
        if (input[0] >= -57.47) {
            var66 = 0.0073487544;
        } else {
            var66 = 0.024713982;
        }
    }
    double var67;
    if (input[5] >= 0.0049505) {
        var67 = -0.022751404;
    } else {
        var67 = 0.023528958;
    }
    double var68;
    if (input[6] >= 102.53556) {
        var68 = -0.022347813;
    } else {
        if (input[0] >= -57.36) {
            var68 = 0.00667614;
        } else {
            var68 = 0.02413324;
        }
    }
    double var69;
    if (input[5] >= 0.0147545) {
        var69 = -0.022278816;
    } else {
        if (input[0] >= -57.36) {
            var69 = 0.006632847;
        } else {
            var69 = 0.02424423;
        }
    }
    double var70;
    if (input[5] >= 0.0147545) {
        var70 = -0.022160439;
    } else {
        if (input[0] >= -57.21) {
            var70 = 0.0043790406;
        } else {
            var70 = 0.02426312;
        }
    }
    double var71;
    if (input[5] >= 0.0147545) {
        var71 = -0.021938812;
    } else {
        if (input[0] >= -57.36) {
            var71 = 0.0047362456;
        } else {
            var71 = 0.024021206;
        }
    }
    double var72;
    if (input[5] >= 0.0147545) {
        var72 = -0.021939447;
    } else {
        if (input[0] >= -57.300003) {
            var72 = 0.005064496;
        } else {
            var72 = 0.023842275;
        }
    }
    double var73;
    if (input[10] >= 9.887299) {
        if (input[0] >= -57.905) {
            var73 = 0.00865551;
        } else {
            var73 = 0.023379903;
        }
    } else {
        var73 = -0.020849956;
    }
    double var74;
    if (input[10] >= 9.887299) {
        var74 = 0.021622213;
    } else {
        var74 = -0.019895788;
    }
    double var75;
    if (input[5] >= 0.0049505) {
        var75 = -0.021919852;
    } else {
        var75 = 0.022226315;
    }
    double var76;
    if (input[10] >= 9.887299) {
        var76 = 0.021250537;
    } else {
        var76 = -0.02041472;
    }
    double var77;
    if (input[6] >= 102.53556) {
        var77 = -0.021157239;
    } else {
        if (input[1] >= 26.1843) {
            var77 = 0.008767765;
        } else {
            var77 = 0.023075517;
        }
    }
    double var78;
    if (input[5] >= 0.0049505) {
        var78 = -0.021635082;
    } else {
        var78 = 0.021426259;
    }
    double var79;
    if (input[5] >= 0.0147545) {
        var79 = -0.020839438;
    } else {
        if (input[0] >= -57.835) {
            var79 = 0.007896836;
        } else {
            var79 = 0.022851815;
        }
    }
    double var80;
    if (input[10] >= 9.887299) {
        var80 = 0.019567406;
    } else {
        var80 = -0.020017318;
    }
    double var81;
    if (input[5] >= 0.0147545) {
        var81 = -0.020648386;
    } else {
        if (input[10] >= 9.975559) {
            var81 = 0.022390764;
        } else {
            var81 = 0.006902122;
        }
    }
    double var82;
    if (input[5] >= 0.0147545) {
        var82 = -0.020585096;
    } else {
        var82 = 0.019245295;
    }
    double var83;
    if (input[10] >= 9.96216) {
        var83 = 0.022256978;
    } else {
        if (input[7] >= 487.70532) {
            var83 = -0.019746758;
        } else {
            var83 = -0.00590962;
        }
    }
    double var84;
    if (input[5] >= 0.0147545) {
        var84 = -0.020155685;
    } else {
        var84 = 0.01946726;
    }
    double var85;
    if (input[5] >= 0.0147545) {
        var85 = -0.019982828;
    } else {
        if (input[0] >= -58.055) {
            var85 = 0.007589982;
        } else {
            var85 = 0.021462027;
        }
    }
    double var86;
    if (input[5] >= 0.0147545) {
        var86 = -0.020024644;
    } else {
        if (input[0] >= -58.055) {
            var86 = 0.005896721;
        } else {
            var86 = 0.021412771;
        }
    }
    double var87;
    if (input[5] >= 0.0147545) {
        var87 = -0.019578656;
    } else {
        if (input[0] >= -58.1) {
            var87 = 0.005788705;
        } else {
            var87 = 0.02079942;
        }
    }
    double var88;
    if (input[5] >= 0.0147545) {
        var88 = -0.019594148;
    } else {
        if (input[0] >= -58.055) {
            var88 = 0.005910387;
        } else {
            var88 = 0.020688731;
        }
    }
    double var89;
    if (input[6] >= 102.53556) {
        var89 = -0.019461833;
    } else {
        var89 = 0.017973447;
    }
    double var90;
    if (input[5] >= 0.0049505) {
        var90 = -0.020520724;
    } else {
        var90 = 0.020330181;
    }
    double var91;
    if (input[5] >= 0.0049505) {
        var91 = -0.019885333;
    } else {
        var91 = 0.01982881;
    }
    double var92;
    if (input[5] >= 0.0147545) {
        var92 = -0.018999627;
    } else {
        var92 = 0.016822822;
    }
    double var93;
    if (input[5] >= 0.0147545) {
        var93 = -0.01889562;
    } else {
        var93 = 0.01720359;
    }
    double var94;
    if (input[10] >= 9.96216) {
        var94 = 0.02032294;
    } else {
        var94 = -0.015157595;
    }
    double var95;
    if (input[10] >= 9.96216) {
        var95 = 0.02024959;
    } else {
        var95 = -0.013729738;
    }
    double var96;
    if (input[5] >= 0.0147545) {
        var96 = -0.018312557;
    } else {
        var96 = 0.018084971;
    }
    double var97;
    if (input[10] >= 9.96216) {
        var97 = 0.020096289;
    } else {
        var97 = -0.013770944;
    }
    double var98;
    if (input[10] >= 9.887299) {
        var98 = 0.017390879;
    } else {
        var98 = -0.01756972;
    }
    double var99;
    if (input[5] >= 0.0049505) {
        var99 = -0.014427719;
    } else {
        var99 = 0.019037515;
    }
    double var100;
    if (input[10] >= 9.96216) {
        var100 = 0.019335592;
    } else {
        var100 = -0.014975964;
    }
    double var101;
    if (input[5] >= 0.0147545) {
        var101 = -0.017762367;
    } else {
        var101 = 0.015853269;
    }
    double var102;
    if (input[5] >= 0.0049505) {
        var102 = -0.013820127;
    } else {
        var102 = 0.018436091;
    }
    double var103;
    if (input[5] >= 0.0147545) {
        var103 = -0.01734898;
    } else {
        var103 = 0.01615279;
    }
    double var104;
    if (input[5] >= 0.0049505) {
        var104 = -0.013298586;
    } else {
        var104 = 0.018287037;
    }
    double var105;
    if (input[5] >= 0.0147545) {
        var105 = -0.01731069;
    } else {
        var105 = 0.017002739;
    }
    double var106;
    if (input[5] >= 0.0049505) {
        var106 = -0.0129293455;
    } else {
        var106 = 0.017887177;
    }
    double var107;
    if (input[5] >= 0.0049505) {
        var107 = -0.012393738;
    } else {
        var107 = 0.017295996;
    }
    double var108;
    if (input[10] >= 9.944315) {
        var108 = 0.016185729;
    } else {
        var108 = -0.012006507;
    }
    double var109;
    if (input[5] >= 0.0049505) {
        var109 = -0.012975918;
    } else {
        var109 = 0.017210193;
    }
    double var110;
    if (input[10] >= 9.887299) {
        var110 = 0.015328715;
    } else {
        var110 = -0.017024387;
    }
    double var111;
    if (input[5] >= 0.0049505) {
        var111 = -0.018059438;
    } else {
        var111 = 0.017252408;
    }
    double var112;
    if (input[5] >= 0.0049505) {
        var112 = -0.011853832;
    } else {
        var112 = 0.017244099;
    }
    double var113;
    if (input[5] >= 0.0049505) {
        var113 = -0.012070851;
    } else {
        var113 = 0.017029887;
    }
    double var114;
    if (input[10] >= 9.900009) {
        var114 = 0.016750133;
    } else {
        var114 = -0.0126281185;
    }
    double var115;
    if (input[0] >= -57.065002) {
        var115 = -0.012387672;
    } else {
        var115 = 0.012826706;
    }
    double var116;
    if (input[0] >= -57.684998) {
        var116 = -0.012477622;
    } else {
        var116 = 0.014246314;
    }
    double var117;
    if (input[3] >= -47.0) {
        var117 = -0.011866135;
    } else {
        var117 = 0.014907631;
    }
    double var118;
    if (input[10] >= 9.90197) {
        var118 = 0.013094409;
    } else {
        var118 = -0.012641034;
    }
    double var119;
    if (input[10] >= 9.9009905) {
        var119 = 0.014354889;
    } else {
        var119 = -0.012636058;
    }
    double var120;
    if (input[3] >= -47.0) {
        var120 = -0.010883683;
    } else {
        var120 = 0.014828833;
    }
    double var121;
    if (input[0] >= -57.265) {
        var121 = -0.011424205;
    } else {
        var121 = 0.01339974;
    }
    double var122;
    if (input[0] >= -57.265) {
        var122 = -0.012662542;
    } else {
        var122 = 0.013564735;
    }
    double var123;
    if (input[10] >= 9.90933) {
        var123 = 0.013583923;
    } else {
        var123 = -0.010922681;
    }
    double var124;
    if (input[0] >= -57.075) {
        var124 = -0.01090539;
    } else {
        var124 = 0.012444843;
    }
    double var125;
    if (input[10] >= 9.92359) {
        var125 = 0.011475413;
    } else {
        var125 = -0.009073325;
    }
    double var126;
    if (input[6] >= 109.59596) {
        var126 = -0.03279678;
    } else {
        if (input[6] >= 100.50505) {
            if (input[3] >= -46.0) {
                var126 = 0.09521913;
            } else {
                var126 = 0.03846154;
            }
        } else {
            var126 = -0.0322449;
        }
    }
    double var127;
    if (input[10] >= 9.061802) {
        if (input[5] >= 0.0049505) {
            var127 = 0.087008916;
        } else {
            var127 = -0.031989984;
        }
    } else {
        var127 = -0.03241881;
    }
    double var128;
    if (input[6] >= 110.10101) {
        var128 = -0.032059174;
    } else {
        if (input[6] >= 100.50505) {
            var128 = 0.07982928;
        } else {
            var128 = -0.031557675;
        }
    }
    double var129;
    if (input[10] >= 9.061802) {
        if (input[7] >= 49.9949) {
            var129 = 0.07427836;
        } else {
            var129 = -0.031265754;
        }
    } else {
        var129 = -0.031714283;
    }
    double var130;
    if (input[10] >= 9.061802) {
        if (input[5] >= 0.0049505) {
            var130 = 0.06908802;
        } else {
            var130 = -0.030969093;
        }
    } else {
        var130 = -0.03139608;
    }
    double var131;
    if (input[10] >= 9.061802) {
        if (input[5] >= 0.0049505) {
            var131 = 0.06614309;
        } else {
            var131 = -0.030522902;
        }
    } else {
        var131 = -0.031076362;
    }
    double var132;
    if (input[10] >= 9.061802) {
        if (input[6] >= 100.50505) {
            var132 = 0.05978501;
        } else {
            var132 = -0.030279774;
        }
    } else {
        var132 = -0.030755578;
    }
    double var133;
    if (input[5] >= 0.086739) {
        var133 = -0.030459201;
    } else {
        if (input[5] >= 0.0049505) {
            var133 = 0.057834893;
        } else {
            var133 = -0.030019606;
        }
    }
    double var134;
    if (input[5] >= 0.086739) {
        var134 = -0.030181486;
    } else {
        if (input[5] >= 0.0049505) {
            var134 = 0.05389441;
        } else {
            var134 = -0.029638683;
        }
    }
    double var135;
    if (input[10] >= 9.061802) {
        if (input[5] >= 0.0049505) {
            var135 = 0.05125426;
        } else {
            var135 = -0.029448835;
        }
    } else {
        var135 = -0.029892717;
    }
    double var136;
    if (input[10] >= 9.061802) {
        if (input[5] >= 0.0049505) {
            var136 = 0.05035446;
        } else {
            var136 = -0.029074907;
        }
    } else {
        var136 = -0.029639075;
    }
    double var137;
    if (input[5] >= 0.086739) {
        var137 = -0.02936737;
    } else {
        if (input[5] >= 0.0049505) {
            var137 = 0.04724224;
        } else {
            var137 = -0.0289409;
        }
    }
    double var138;
    if (input[10] >= 9.061802) {
        if (input[5] >= 0.0049505) {
            if (input[3] >= -46.0) {
                var138 = 0.04744407;
            } else {
                var138 = 0.021848245;
            }
        } else {
            var138 = -0.028560588;
        }
    } else {
        var138 = -0.029118875;
    }
    double var139;
    if (input[10] >= 9.061802) {
        if (input[5] >= 0.0049505) {
            if (input[5] >= 0.0147545) {
                if (input[0] >= -51.765) {
                    var139 = 0.020651279;
                } else {
                    var139 = 0.045723084;
                }
            } else {
                var139 = 0.02020821;
            }
        } else {
            var139 = -0.028324112;
        }
    } else {
        var139 = -0.028887987;
    }
    double var140;
    if (input[5] >= 0.086739) {
        var140 = -0.028678834;
    } else {
        if (input[5] >= 0.0049505) {
            if (input[5] >= 0.0147545) {
                var140 = 0.04296251;
            } else {
                var140 = 0.019523028;
            }
        } else {
            var140 = -0.02800187;
        }
    }
    double var141;
    if (input[10] >= 9.061399) {
        if (input[5] >= 0.0049505) {
            var141 = 0.04081732;
        } else {
            var141 = -0.027721612;
        }
    } else {
        var141 = -0.02842978;
    }
    double var142;
    if (input[10] >= 9.061802) {
        if (input[5] >= 0.0049505) {
            if (input[10] >= 9.215321) {
                var142 = 0.041653436;
            } else {
                var142 = 0.019007115;
            }
        } else {
            var142 = -0.027543176;
        }
    } else {
        var142 = -0.028222432;
    }
    double var143;
    if (input[5] >= 0.09083401) {
        var143 = -0.0280448;
    } else {
        if (input[5] >= 0.0049505) {
            if (input[3] >= -46.0) {
                var143 = 0.03947563;
            } else {
                var143 = 0.016363297;
            }
        } else {
            var143 = -0.02731353;
        }
    }
    double var144;
    if (input[10] >= 9.169266) {
        if (input[6] >= 100.50505) {
            if (input[0] >= -57.68) {
                var144 = 0.039256603;
            } else {
                var144 = 0.015090232;
            }
        } else {
            var144 = -0.027090091;
        }
    } else {
        var144 = -0.028075486;
    }
    double var145;
    if (input[5] >= 0.086739) {
        var145 = -0.027636832;
    } else {
        if (input[5] >= 0.0049505) {
            if (input[0] >= -52.325) {
                var145 = 0.0154951885;
            } else {
                var145 = 0.038556453;
            }
        } else {
            var145 = -0.02697511;
        }
    }
    double var146;
    if (input[5] >= 0.086739) {
        var146 = -0.027467823;
    } else {
        if (input[5] >= 0.0049505) {
            if (input[0] >= -57.875) {
                if (input[0] >= -51.765) {
                    var146 = 0.01790141;
                } else {
                    var146 = 0.037614603;
                }
            } else {
                var146 = 0.014057345;
            }
        } else {
            var146 = -0.026756931;
        }
    }
    double var147;
    if (input[10] >= 9.061802) {
        if (input[5] >= 0.0049505) {
            if (input[10] >= 9.215321) {
                var147 = 0.036856867;
            } else {
                var147 = 0.01601023;
            }
        } else {
            var147 = -0.026601523;
        }
    } else {
        var147 = -0.027213225;
    }
    double var148;
    if (input[10] >= 9.061802) {
        if (input[6] >= 100.50505) {
            if (input[0] >= -57.66) {
                if (input[0] >= -51.765) {
                    var148 = 0.016593512;
                } else {
                    var148 = 0.035988998;
                }
            } else {
                var148 = 0.012460155;
            }
        } else {
            var148 = -0.026341293;
        }
    } else {
        var148 = -0.027119169;
    }
    double var149;
    if (input[10] >= 9.185728) {
        if (input[6] >= 100.50505) {
            if (input[0] >= -57.875) {
                var149 = 0.035285234;
            } else {
                var149 = 0.012186679;
            }
        } else {
            var149 = -0.026079113;
        }
    } else {
        var149 = -0.027300382;
    }
    double var150;
    if (input[10] >= 9.070199) {
        if (input[5] >= 0.0049505) {
            if (input[5] >= 0.0147545) {
                var150 = 0.034560304;
            } else {
                var150 = 0.014603294;
            }
        } else {
            var150 = -0.025952384;
        }
    } else {
        var150 = -0.026794964;
    }
    double var151;
    if (input[5] >= 0.086739) {
        var151 = -0.026587257;
    } else {
        if (input[5] >= 0.0049505) {
            if (input[0] >= -57.875) {
                var151 = 0.034203943;
            } else {
                var151 = 0.010854132;
            }
        } else {
            var151 = -0.025820732;
        }
    }
    double var152;
    if (input[10] >= 9.061802) {
        if (input[7] >= 49.9949) {
            if (input[0] >= -51.765) {
                var152 = 0.013867331;
            } else {
                var152 = 0.033651274;
            }
        } else {
            var152 = -0.025608776;
        }
    } else {
        var152 = -0.02644656;
    }
    double var153;
    if (input[10] >= 9.070199) {
        if (input[6] >= 100.50505) {
            if (input[0] >= -57.875) {
                var153 = 0.032808285;
            } else {
                var153 = 0.009398921;
            }
        } else {
            var153 = -0.02531988;
        }
    } else {
        var153 = -0.02636521;
    }
    double var154;
    if (input[5] >= 0.086739) {
        var154 = -0.026214277;
    } else {
        if (input[5] >= 0.0049505) {
            if (input[5] >= 0.0147545) {
                var154 = 0.031279273;
            } else {
                var154 = 0.008865601;
            }
        } else {
            var154 = -0.025320878;
        }
    }
    double var155;
    if (input[5] >= 0.09083401) {
        var155 = -0.025987223;
    } else {
        if (input[10] >= 9.887299) {
            if (input[0] >= -57.115) {
                var155 = -0.0012905439;
            } else {
                var155 = -0.026398221;
            }
        } else {
            if (input[0] >= -51.765) {
                var155 = 0.009389249;
            } else {
                var155 = 0.031663675;
            }
        }
    }
    double var156;
    if (input[6] >= 109.59596) {
        var156 = -0.025934948;
    } else {
        if (input[10] >= 9.957216) {
            var156 = -0.026212448;
        } else {
            if (input[3] >= -46.0) {
                if (input[10] >= 9.215321) {
                    var156 = 0.031313237;
                } else {
                    var156 = 0.011778808;
                }
            } else {
                var156 = 0.0077513815;
            }
        }
    }
    double var157;
    if (input[10] >= 9.061802) {
        if (input[10] >= 9.887299) {
            if (input[10] >= 9.957216) {
                var157 = -0.026135553;
            } else {
                var157 = -0.001796495;
            }
        } else {
            var157 = 0.030966047;
        }
    } else {
        var157 = -0.025677431;
    }
    double var158;
    if (input[10] >= 9.061802) {
        if (input[10] >= 9.887299) {
            if (input[0] >= -57.635) {
                var158 = -0.00980376;
            } else {
                var158 = -0.025928158;
            }
        } else {
            if (input[10] >= 9.215321) {
                var158 = 0.030500546;
            } else {
                var158 = 0.010726538;
            }
        }
    } else {
        var158 = -0.025620027;
    }
    double var159;
    if (input[5] >= 0.086739) {
        var159 = -0.025486741;
    } else {
        if (input[5] >= 0.0049505) {
            var159 = 0.030651717;
        } else {
            var159 = -0.024549974;
        }
    }
    double var160;
    if (input[10] >= 9.061802) {
        if (input[6] >= 100.50505) {
            if (input[0] >= -52.35) {
                var160 = 0.008919447;
            } else {
                var160 = 0.030063799;
            }
        } else {
            var160 = -0.024209265;
        }
    } else {
        var160 = -0.02543196;
    }
    double var161;
    if (input[10] >= 9.169266) {
        if (input[10] >= 9.96216) {
            var161 = -0.02576801;
        } else {
            if (input[5] >= 0.0147545) {
                var161 = 0.029370114;
            } else {
                var161 = 0.010624496;
            }
        }
    } else {
        var161 = -0.025844783;
    }
    double var162;
    if (input[10] >= 9.061802) {
        if (input[10] >= 9.957216) {
            var162 = -0.025525589;
        } else {
            if (input[5] >= 0.0147545) {
                if (input[0] >= -52.35) {
                    var162 = 0.007978339;
                } else {
                    var162 = 0.029173234;
                }
            } else {
                var162 = 0.0034744495;
            }
        }
    } else {
        var162 = -0.02511986;
    }
    double var163;
    if (input[10] >= 9.061802) {
        if (input[5] >= 0.0049505) {
            if (input[0] >= -57.735) {
                if (input[0] >= -51.765) {
                    var163 = 0.010193699;
                } else {
                    var163 = 0.029095693;
                }
            } else {
                var163 = 0.0085272705;
            }
        } else {
            var163 = -0.023955133;
        }
    } else {
        var163 = -0.024970658;
    }
    double var164;
    if (input[5] >= 0.09083401) {
        var164 = -0.024860924;
    } else {
        if (input[5] >= 0.0049505) {
            if (input[0] >= -52.35) {
                var164 = 0.0073048617;
            } else {
                var164 = 0.028972602;
            }
        } else {
            var164 = -0.023799947;
        }
    }
    double var165;
    if (input[10] >= 9.169266) {
        if (input[10] >= 9.96216) {
            var165 = -0.0253299;
        } else {
            if (input[3] >= -46.0) {
                var165 = 0.028339041;
            } else {
                var165 = 0.009104283;
            }
        }
    } else {
        var165 = -0.025459725;
    }
    double var166;
    if (input[10] >= 9.061802) {
        if (input[10] >= 9.889259) {
            var166 = -0.023042677;
        } else {
            if (input[0] >= -51.765) {
                var166 = 0.009143001;
            } else {
                var166 = 0.027934102;
            }
        }
    } else {
        var166 = -0.024661725;
    }
    double var167;
    if (input[10] >= 9.169266) {
        if (input[10] >= 9.96216) {
            var167 = -0.02490746;
        } else {
            if (input[3] >= -46.0) {
                var167 = 0.027723243;
            } else {
                var167 = 0.0044487016;
            }
        }
    } else {
        var167 = -0.025273776;
    }
    double var168;
    if (input[6] >= 109.59596) {
        var168 = -0.024291702;
    } else {
        if (input[10] >= 9.96216) {
            var168 = -0.02487772;
        } else {
            if (input[6] >= 101.51515) {
                var168 = 0.027831811;
            } else {
                var168 = 0.008860368;
            }
        }
    }
    double var169;
    if (input[10] >= 9.061802) {
        if (input[6] >= 100.50505) {
            if (input[0] >= -52.92) {
                var169 = 0.0072430307;
            } else {
                var169 = 0.027799306;
            }
        } else {
            var169 = -0.022915121;
        }
    } else {
        var169 = -0.024245178;
    }
    double var170;
    if (input[5] >= 0.086739) {
        var170 = -0.024220247;
    } else {
        if (input[5] >= 0.0049505) {
            if (input[2] >= -73.0) {
                if (input[5] >= 0.0697475) {
                    var170 = 0.012461473;
                } else {
                    var170 = 0.026797637;
                }
            } else {
                var170 = 0.00907726;
            }
        } else {
            var170 = -0.022880344;
        }
    }
    double var171;
    if (input[10] >= 9.061802) {
        if (input[10] >= 9.96216) {
            var171 = -0.024535714;
        } else {
            if (input[0] >= -53.145) {
                var171 = 0.00794012;
            } else {
                if (input[5] >= 0.0147545) {
                    var171 = 0.027089505;
                } else {
                    var171 = 0.010837755;
                }
            }
        }
    } else {
        var171 = -0.024018997;
    }
    double var172;
    if (input[5] >= 0.086739) {
        var172 = -0.023819976;
    } else {
        if (input[5] >= 0.0147545) {
            if (input[0] >= -52.96) {
                var172 = 0.007432993;
            } else {
                var172 = 0.026330326;
            }
        } else {
            if (input[0] >= -57.725) {
                var172 = -0.0058817193;
            } else {
                var172 = -0.024335515;
            }
        }
    }
    double var173;
    if (input[5] >= 0.086739) {
        var173 = -0.023774417;
    } else {
        if (input[5] >= 0.0049505) {
            if (input[0] >= -57.735) {
                if (input[0] >= -52.92) {
                    var173 = 0.0075125466;
                } else {
                    var173 = 0.026354922;
                }
            } else {
                var173 = 0.005859567;
            }
        } else {
            var173 = -0.02232038;
        }
    }
    double var174;
    if (input[10] >= 9.061802) {
        if (input[10] >= 9.96216) {
            var174 = -0.024170747;
        } else {
            if (input[0] >= -57.629997) {
                if (input[0] >= -52.35) {
                    var174 = 0.007583742;
                } else {
                    var174 = 0.026447976;
                }
            } else {
                var174 = 0.0067654476;
            }
        }
    } else {
        var174 = -0.023655832;
    }
    double var175;
    if (input[5] >= 0.086739) {
        var175 = -0.023654284;
    } else {
        if (input[10] >= 9.96216) {
            var175 = -0.023924338;
        } else {
            if (input[0] >= -52.35) {
                var175 = 0.007309112;
            } else {
                if (input[10] >= 9.8648615) {
                    var175 = 0.008106354;
                } else {
                    var175 = 0.026330218;
                }
            }
        }
    }
    double var176;
    if (input[10] >= 9.061399) {
        if (input[10] >= 9.957216) {
            var176 = -0.023866264;
        } else {
            if (input[10] >= 9.8648615) {
                var176 = 0.0075854696;
            } else {
                if (input[2] >= -64.0) {
                    var176 = 0.01030668;
                } else {
                    var176 = 0.026080748;
                }
            }
        }
    } else {
        var176 = -0.023291854;
    }
    double var177;
    if (input[10] >= 9.061399) {
        if (input[10] >= 9.96216) {
            var177 = -0.023563076;
        } else {
            if (input[0] >= -52.35) {
                var177 = 0.0067141317;
            } else {
                if (input[10] >= 9.865349) {
                    var177 = 0.007406141;
                } else {
                    var177 = 0.025892327;
                }
            }
        }
    } else {
        var177 = -0.023317397;
    }
    double var178;
    if (input[10] >= 9.061802) {
        if (input[10] >= 9.96216) {
            var178 = -0.023426589;
        } else {
            if (input[1] >= 22.84755) {
                var178 = 0.025040016;
            } else {
                if (input[1] >= 20.507149) {
                    var178 = 0.0019061819;
                } else {
                    var178 = 0.01639862;
                }
            }
        }
    } else {
        var178 = -0.023168026;
    }
    double var179;
    if (input[10] >= 9.061802) {
        if (input[10] >= 9.96216) {
            var179 = -0.023371946;
        } else {
            if (input[10] >= 9.816585) {
                var179 = 0.0061748913;
            } else {
                if (input[0] >= -52.96) {
                    var179 = 0.007007479;
                } else {
                    var179 = 0.025575643;
                }
            }
        }
    } else {
        var179 = -0.023039779;
    }
    double var180;
    if (input[10] >= 9.061802) {
        if (input[10] >= 9.96216) {
            var180 = -0.023228044;
        } else {
            if (input[0] >= -52.96) {
                var180 = 0.0063426956;
            } else {
                if (input[5] >= 0.0147545) {
                    var180 = 0.025411973;
                } else {
                    var180 = 0.008183074;
                }
            }
        }
    } else {
        var180 = -0.022895662;
    }
    double var181;
    if (input[10] >= 9.061802) {
        if (input[10] >= 9.96216) {
            var181 = -0.02288874;
        } else {
            if (input[0] >= -53.145) {
                var181 = 0.007037618;
            } else {
                if (input[0] >= -57.41) {
                    var181 = 0.025490398;
                } else {
                    var181 = 0.0073032044;
                }
            }
        }
    } else {
        var181 = -0.02283969;
    }
    double var182;
    if (input[10] >= 9.061802) {
        if (input[10] >= 9.96216) {
            var182 = -0.022691717;
        } else {
            if (input[0] >= -52.96) {
                var182 = 0.0072259265;
            } else {
                if (input[0] >= -57.255) {
                    var182 = 0.025099603;
                } else {
                    var182 = 0.007841534;
                }
            }
        }
    } else {
        var182 = -0.02279718;
    }
    double var183;
    if (input[3] >= -46.0) {
        if (input[5] >= 0.09083401) {
            var183 = -0.02071814;
        } else {
            if (input[0] >= -53.335) {
                var183 = 0.0063802092;
            } else {
                var183 = 0.024160165;
            }
        }
    } else {
        var183 = -0.02102195;
    }
    double var184;
    if (input[10] >= 9.061802) {
        if (input[5] >= 0.0049505) {
            if (input[3] >= -43.0) {
                var184 = 0.007436059;
            } else {
                var184 = 0.025046308;
            }
        } else {
            var184 = -0.020597562;
        }
    } else {
        var184 = -0.022312352;
    }
    double var185;
    if (input[10] >= 9.061802) {
        if (input[10] >= 9.96216) {
            var185 = -0.022245938;
        } else {
            if (input[0] >= -52.96) {
                var185 = 0.00644017;
            } else {
                if (input[10] >= 9.776606) {
                    var185 = 0.0075440155;
                } else {
                    var185 = 0.024603289;
                }
            }
        }
    } else {
        var185 = -0.02249647;
    }
    double var186;
    if (input[5] >= 0.086739) {
        var186 = -0.022239674;
    } else {
        if (input[10] >= 9.96216) {
            var186 = -0.022353312;
        } else {
            if (input[1] >= 20.57875) {
                if (input[0] >= -57.12) {
                    var186 = 0.024542429;
                } else {
                    var186 = 0.008901945;
                }
            } else {
                var186 = 0.0051133763;
            }
        }
    }
    double var187;
    if (input[10] >= 9.061399) {
        if (input[10] >= 9.96216) {
            var187 = -0.022179348;
        } else {
            if (input[1] >= 21.11015) {
                var187 = 0.022819167;
            } else {
                var187 = 0.0073885233;
            }
        }
    } else {
        var187 = -0.022156605;
    }
    double var188;
    if (input[10] >= 9.061802) {
        if (input[10] >= 9.957216) {
            var188 = -0.021837212;
        } else {
            if (input[0] >= -53.145) {
                var188 = 0.00643053;
            } else {
                if (input[0] >= -57.225) {
                    var188 = 0.02423533;
                } else {
                    var188 = 0.007357637;
                }
            }
        }
    } else {
        var188 = -0.021959735;
    }
    double var189;
    if (input[5] >= 0.086739) {
        var189 = -0.021753361;
    } else {
        if (input[5] >= 0.0147545) {
            if (input[0] >= -54.485) {
                var189 = 0.006457161;
            } else {
                var189 = 0.023898935;
            }
        } else {
            if (input[0] >= -58.53) {
                var189 = -0.0046510794;
            } else {
                var189 = -0.020948613;
            }
        }
    }
    double var190;
    if (input[10] >= 9.169266) {
        if (input[10] >= 9.888279) {
            var190 = -0.019275425;
        } else {
            var190 = 0.023222907;
        }
    } else {
        var190 = -0.023150811;
    }
    double var191;
    if (input[10] >= 9.169266) {
        if (input[5] >= 0.0049505) {
            var191 = 0.024098035;
        } else {
            var191 = -0.019137865;
        }
    } else {
        var191 = -0.023091856;
    }
    double var192;
    if (input[10] >= 9.061802) {
        if (input[10] >= 9.887299) {
            var192 = -0.019411655;
        } else {
            if (input[1] >= 20.930698) {
                var192 = 0.023794683;
            } else {
                var192 = 0.0057915538;
            }
        }
    } else {
        var192 = -0.021474786;
    }
    double var193;
    if (input[10] >= 9.061399) {
        if (input[10] >= 9.96216) {
            var193 = -0.021290017;
        } else {
            if (input[0] >= -53.504997) {
                var193 = 0.0069991173;
            } else {
                if (input[0] >= -56.955) {
                    var193 = 0.023560246;
                } else {
                    var193 = 0.008082829;
                }
            }
        }
    } else {
        var193 = -0.021337971;
    }
    double var194;
    if (input[10] >= 9.061802) {
        if (input[10] >= 9.96216) {
            var194 = -0.021100432;
        } else {
            if (input[1] >= 20.930698) {
                var194 = 0.021462588;
            } else {
                var194 = 0.0073032416;
            }
        }
    } else {
        var194 = -0.021163862;
    }
    double var195;
    if (input[10] >= 9.061802) {
        if (input[10] >= 9.96216) {
            var195 = -0.020871392;
        } else {
            if (input[0] >= -57.075) {
                var195 = 0.023872312;
            } else {
                var195 = 0.008009928;
            }
        }
    } else {
        var195 = -0.021098744;
    }
    double var196;
    if (input[5] >= 0.086739) {
        var196 = -0.020584034;
    } else {
        if (input[10] >= 9.96216) {
            var196 = -0.02051389;
        } else {
            if (input[0] >= -56.885002) {
                var196 = 0.022539193;
            } else {
                var196 = 0.008438243;
            }
        }
    }
    double var197;
    if (input[10] >= 9.169266) {
        if (input[10] >= 9.96216) {
            var197 = -0.02041805;
        } else {
            if (input[0] >= -56.885002) {
                var197 = 0.022407686;
            } else {
                var197 = 0.00825099;
            }
        }
    } else {
        var197 = -0.02240597;
    }
    double var198;
    if (input[10] >= 9.061802) {
        if (input[5] >= 0.0049505) {
            if (input[1] >= 20.57875) {
                var198 = 0.023553198;
            } else {
                var198 = 0.0068159113;
            }
        } else {
            var198 = -0.018170746;
        }
    } else {
        var198 = -0.020269843;
    }
    double var199;
    if (input[6] >= 109.59596) {
        var199 = -0.020005725;
    } else {
        if (input[10] >= 9.957216) {
            var199 = -0.020173226;
        } else {
            if (input[4] >= 21.5) {
                var199 = 0.021237435;
            } else {
                var199 = 0.0054015885;
            }
        }
    }
    double var200;
    if (input[10] >= 9.061802) {
        if (input[5] >= 0.0049505) {
            if (input[1] >= 21.52975) {
                var200 = 0.02272359;
            } else {
                var200 = 0.0066099786;
            }
        } else {
            var200 = -0.017663805;
        }
    } else {
        var200 = -0.02020719;
    }
    double var201;
    if (input[10] >= 9.05939) {
        if (input[10] >= 9.96216) {
            var201 = -0.019884575;
        } else {
            if (input[1] >= 21.52975) {
                var201 = 0.020603059;
            } else {
                var201 = 0.0047017517;
            }
        }
    } else {
        var201 = -0.020185843;
    }
    double var202;
    if (input[3] >= -46.0) {
        if (input[5] >= 0.086739) {
            var202 = -0.017295426;
        } else {
            var202 = 0.021577993;
        }
    } else {
        var202 = -0.018022342;
    }
    double var203;
    if (input[10] >= 9.061802) {
        if (input[10] >= 9.944315) {
            var203 = -0.016064271;
        } else {
            var203 = 0.020647835;
        }
    } else {
        var203 = -0.020086724;
    }
    double var204;
    if (input[10] >= 9.061399) {
        if (input[3] >= -46.0) {
            if (input[0] >= -54.65) {
                var204 = 0.0070730373;
            } else {
                var204 = 0.020981733;
            }
        } else {
            var204 = -0.01422885;
        }
    } else {
        var204 = -0.019412564;
    }
    double var205;
    if (input[6] >= 110.10101) {
        var205 = -0.019285915;
    } else {
        if (input[10] >= 9.887299) {
            var205 = -0.01654855;
        } else {
            if (input[0] >= -55.125) {
                var205 = 0.006858479;
            } else {
                var205 = 0.021629993;
            }
        }
    }
    double var206;
    if (input[5] >= 0.086739) {
        var206 = -0.019282287;
    } else {
        if (input[3] >= -46.0) {
            if (input[1] >= 21.7731) {
                var206 = 0.020561438;
            } else {
                var206 = 0.0069709714;
            }
        } else {
            var206 = -0.01423976;
        }
    }
    double var207;
    if (input[3] >= -46.0) {
        if (input[7] >= 986.63403) {
            var207 = -0.013900538;
        } else {
            var207 = 0.020708827;
        }
    } else {
        var207 = -0.01641037;
    }
    double var208;
    if (input[10] >= 9.061802) {
        if (input[3] >= -46.0) {
            if (input[0] >= -54.745) {
                var208 = 0.0069111274;
            } else {
                var208 = 0.020799095;
            }
        } else {
            var208 = -0.015300474;
        }
    } else {
        var208 = -0.019102154;
    }
    double var209;
    if (input[10] >= 9.185728) {
        if (input[3] >= -46.0) {
            var209 = 0.020348415;
        } else {
            var209 = -0.012681298;
        }
    } else {
        var209 = -0.02115572;
    }
    double var210;
    if (input[10] >= 9.061399) {
        if (input[5] >= 0.0147545) {
            if (input[1] >= 23.85815) {
                var210 = 0.020284085;
            } else {
                var210 = 0.0069158557;
            }
        } else {
            var210 = -0.0074467594;
        }
    } else {
        var210 = -0.018443666;
    }
    double var211;
    if (input[5] >= 0.086739) {
        var211 = -0.018522974;
    } else {
        if (input[3] >= -46.0) {
            if (input[1] >= 23.4531) {
                var211 = 0.019506471;
            } else {
                var211 = 0.0073537827;
            }
        } else {
            var211 = -0.012700361;
        }
    }
    double var212;
    if (input[3] >= -46.0) {
        if (input[0] >= -53.795) {
            var212 = -0.010860892;
        } else {
            var212 = 0.017928647;
        }
    } else {
        var212 = -0.015698848;
    }
    double var213;
    if (input[10] >= 9.061802) {
        if (input[10] >= 9.888279) {
            var213 = -0.012056711;
        } else {
            if (input[1] >= 23.60535) {
                var213 = 0.020540828;
            } else {
                var213 = 0.0060289577;
            }
        }
    } else {
        var213 = -0.018121224;
    }
    double var214;
    if (input[3] >= -46.0) {
        if (input[9] >= 250.0) {
            var214 = -0.0068940087;
        } else {
            var214 = 0.020169517;
        }
    } else {
        var214 = -0.01591905;
    }
    double var215;
    if (input[3] >= -46.0) {
        if (input[10] >= 9.206832) {
            var215 = 0.019680003;
        } else {
            var215 = -0.00533419;
        }
    } else {
        var215 = -0.015393539;
    }
    double var216;
    if (input[5] >= 0.094856) {
        var216 = -0.01740083;
    } else {
        if (input[5] >= 0.0147545) {
            if (input[1] >= 24.11855) {
                var216 = 0.019611867;
            } else {
                var216 = 0.00718807;
            }
        } else {
            var216 = -0.014733526;
        }
    }
    double var217;
    if (input[10] >= 9.061802) {
        if (input[10] >= 9.888279) {
            var217 = -0.009662009;
        } else {
            if (input[0] >= -55.565002) {
                var217 = 0.0072011612;
            } else {
                var217 = 0.01932078;
            }
        }
    } else {
        var217 = -0.017703597;
    }
    double var218;
    if (input[3] >= -46.0) {
        if (input[10] >= 9.169266) {
            var218 = 0.018654436;
        } else {
            var218 = -0.011070036;
        }
    } else {
        var218 = -0.015630722;
    }
    double var219;
    if (input[5] >= 0.086739) {
        var219 = -0.017095134;
    } else {
        if (input[10] >= 9.887299) {
            var219 = -0.011600926;
        } else {
            var219 = 0.02133298;
        }
    }
    double var220;
    if (input[10] >= 9.061802) {
        if (input[6] >= 101.51515) {
            var220 = 0.015226014;
        } else {
            var220 = -0.008961694;
        }
    } else {
        var220 = -0.017115302;
    }
    double var221;
    if (input[3] >= -46.0) {
        if (input[10] >= 9.169266) {
            var221 = 0.017230967;
        } else {
            var221 = -0.010278301;
        }
    } else {
        var221 = -0.014492719;
    }
    double var222;
    if (input[3] >= -46.0) {
        if (input[10] >= 9.169266) {
            var222 = 0.018562606;
        } else {
            var222 = -0.010271976;
        }
    } else {
        var222 = -0.014220267;
    }
    double var223;
    if (input[3] >= -46.0) {
        if (input[10] >= 9.187847) {
            var223 = 0.018657006;
        } else {
            var223 = -0.010789253;
        }
    } else {
        var223 = -0.01469149;
    }
    double var224;
    if (input[3] >= -46.0) {
        if (input[0] >= -54.440002) {
            var224 = -0.006063982;
        } else {
            var224 = 0.017423172;
        }
    } else {
        var224 = -0.013480723;
    }
    double var225;
    if (input[10] >= 9.169266) {
        if (input[10] >= 9.71537) {
            var225 = -0.0014325049;
        } else {
            var225 = 0.017585052;
        }
    } else {
        var225 = -0.012584272;
    }
    double var226;
    if (input[3] >= -46.0) {
        if (input[10] >= 9.327923) {
            var226 = 0.01674733;
        } else {
            var226 = 0.00007336064;
        }
    } else {
        var226 = -0.013566476;
    }
    double var227;
    if (input[10] >= 9.169266) {
        if (input[5] >= 0.0147545) {
            var227 = 0.018123016;
        } else {
            var227 = -0.005911828;
        }
    } else {
        var227 = -0.01242033;
    }
    double var228;
    if (input[10] >= 9.169266) {
        if (input[10] >= 9.816585) {
            var228 = -0.007743034;
        } else {
            var228 = 0.01767104;
        }
    } else {
        var228 = -0.012479738;
    }
    double var229;
    if (input[3] >= -46.0) {
        var229 = 0.008619395;
    } else {
        var229 = -0.013645853;
    }
    double var230;
    if (input[3] >= -45.0) {
        var230 = 0.00879761;
    } else {
        var230 = -0.011759305;
    }
    double var231;
    if (input[3] >= -45.0) {
        var231 = 0.013400775;
    } else {
        var231 = -0.011065642;
    }
    double var232;
    if (input[10] >= 9.169266) {
        var232 = 0.0066132764;
    } else {
        var232 = -0.012735148;
    }
    double var233;
    if (input[10] >= 9.185728) {
        var233 = 0.00651784;
    } else {
        var233 = -0.0124522075;
    }
    double var234;
    if (input[10] >= 9.169266) {
        var234 = 0.0068669654;
    } else {
        var234 = -0.012296397;
    }
    double var235;
    if (input[10] >= 9.169266) {
        var235 = 0.0074789226;
    } else {
        var235 = -0.012484838;
    }
    double var236;
    if (input[3] >= -45.0) {
        var236 = 0.008220203;
    } else {
        var236 = -0.009969237;
    }
    double var237;
    if (input[3] >= -45.0) {
        var237 = 0.011667771;
    } else {
        var237 = -0.009661923;
    }
    double var238;
    if (input[3] >= -45.0) {
        var238 = 0.0066000163;
    } else {
        var238 = -0.010893344;
    }
    double var239;
    if (input[10] >= 9.185728) {
        var239 = 0.006264332;
    } else {
        var239 = -0.012124277;
    }
    double var240;
    if (input[10] >= 9.169266) {
        var240 = 0.006264895;
    } else {
        var240 = -0.012251643;
    }
    double var241;
    if (input[10] >= 9.169266) {
        var241 = 0.0067520225;
    } else {
        var241 = -0.011653929;
    }
    double var242;
    if (input[10] >= 9.290659) {
        var242 = 0.00848928;
    } else {
        var242 = -0.014827251;
    }
    double var243;
    if (input[10] >= 9.169266) {
        var243 = 0.006177652;
    } else {
        var243 = -0.011396042;
    }
    double var244;
    if (input[10] >= 9.169266) {
        var244 = 0.009580918;
    } else {
        var244 = -0.011588078;
    }
    double var245;
    if (input[0] >= -54.745) {
        var245 = -0.009324638;
    } else {
        var245 = 0.0064487406;
    }
    double var246;
    if (input[10] >= 9.169266) {
        var246 = 0.0055090277;
    } else {
        var246 = -0.01128043;
    }
    double var247;
    if (input[3] >= -45.0) {
        var247 = 0.005105618;
    } else {
        var247 = -0.010937751;
    }
    double var248;
    if (input[3] >= -45.0) {
        var248 = 0.00668119;
    } else {
        var248 = -0.010413952;
    }
    double var249;
    if (input[10] >= 9.169266) {
        var249 = 0.0052653826;
    } else {
        var249 = -0.011380169;
    }
    double var250;
    if (input[10] >= 9.169266) {
        var250 = 0.009049935;
    } else {
        var250 = -0.010927658;
    }
    double var251;
    if (input[1] >= 25.6875) {
        var251 = 0.008234064;
    } else {
        var251 = -0.009248923;
    }
    double var252;
    if (input[10] >= 9.169266) {
        var252 = 0.008225199;
    } else {
        var252 = -0.011224151;
    }
    double var253;
    if (input[0] >= -56.46) {
        var253 = 0.001614726;
    } else {
        var253 = -0.0061176624;
    }
    double var254;
    if (input[10] >= 9.368152) {
        var254 = 0.0043022353;
    } else {
        var254 = -0.0129253445;
    }
    double var255;
    if (input[3] >= -45.0) {
        var255 = 0.0072583715;
    } else {
        var255 = -0.0108856885;
    }
    double var256;
    if (input[1] >= 25.6875) {
        var256 = 0.0080261035;
    } else {
        var256 = -0.009151999;
    }
    double var257;
    if (input[3] >= -45.0) {
        var257 = 0.006547548;
    } else {
        var257 = -0.009535967;
    }
    double var258;
    if (input[3] >= -45.0) {
        var258 = 0.012340398;
    } else {
        var258 = -0.009206848;
    }
    double var259;
    if (input[10] >= 9.206832) {
        var259 = 0.0052328706;
    } else {
        var259 = -0.0094669415;
    }
    double var260;
    if (input[3] >= -45.0) {
        var260 = 0.005294342;
    } else {
        var260 = -0.009192358;
    }
    double var261;
    if (input[3] >= -45.0) {
        var261 = -0.00021918475;
    } else {
        var261 = -0.0103923585;
    }
    double var262;
    if (input[5] >= 0.0697475) {
        var262 = -0.007663884;
    } else {
        var262 = 0.0069748494;
    }
    double var263;
    if (input[10] >= 9.206832) {
        var263 = 0.0065691504;
    } else {
        var263 = -0.009459206;
    }
    double var264;
    if (input[3] >= -45.0) {
        var264 = 0.00545517;
    } else {
        var264 = -0.010411318;
    }
    double var265;
    if (input[1] >= 23.39575) {
        var265 = 0.002960034;
    } else {
        var265 = -0.009389835;
    }
    double var266;
    if (input[1] >= 25.6875) {
        var266 = 0.007534922;
    } else {
        var266 = -0.009242685;
    }
    double var267;
    if (input[5] >= 0.0697475) {
        var267 = -0.0061465744;
    } else {
        var267 = 0.0032537747;
    }
    double var268;
    if (input[3] >= -45.0) {
        var268 = 0.0057969755;
    } else {
        var268 = -0.009511077;
    }
    double var269;
    if (input[1] >= 25.6875) {
        var269 = 0.0086669745;
    } else {
        var269 = -0.009356242;
    }
    double var270;
    if (input[1] >= 25.75475) {
        var270 = 0.007828592;
    } else {
        var270 = -0.009367365;
    }
    double var271;
    if (input[10] >= 9.245575) {
        var271 = 0.0073394016;
    } else {
        var271 = -0.00779836;
    }
    double var272;
    if (input[3] >= -45.0) {
        var272 = 0.0026144665;
    } else {
        var272 = -0.0089970725;
    }
    double var273;
    if (input[3] >= -45.0) {
        var273 = 0.0058555063;
    } else {
        var273 = -0.011013378;
    }
    double var274;
    if (input[10] >= 9.362873) {
        var274 = 0.0038207644;
    } else {
        var274 = -0.0065765525;
    }
    double var275;
    if (input[3] >= -45.0) {
        var275 = 0.0051939874;
    } else {
        var275 = -0.008303855;
    }
    double var276;
    if (input[3] >= -45.0) {
        var276 = 0.0063421293;
    } else {
        var276 = -0.008851856;
    }
    double var277;
    if (input[3] >= -45.0) {
        var277 = 0.0023585442;
    } else {
        var277 = -0.008447383;
    }
    double var278;
    if (input[3] >= -45.0) {
        var278 = 0.0045926417;
    } else {
        var278 = -0.009962621;
    }
    double var279;
    if (input[10] >= 9.27389) {
        var279 = 0.007866308;
    } else {
        var279 = -0.007649598;
    }
    double var280;
    if (input[1] >= 23.39575) {
        var280 = 0.0071185217;
    } else {
        var280 = -0.005950825;
    }
    double var281;
    if (input[3] >= -45.0) {
        var281 = 0.0021020556;
    } else {
        var281 = -0.008812877;
    }
    double var282;
    if (input[3] >= -45.0) {
        var282 = 0.005714405;
    } else {
        var282 = -0.00848613;
    }
    double var283;
    if (input[3] >= -45.0) {
        var283 = 0.011815851;
    } else {
        var283 = -0.0078602545;
    }
    double var284;
    if (input[3] >= -45.0) {
        var284 = 0.005228242;
    } else {
        var284 = -0.007385789;
    }
    double var285;
    if (input[3] >= -45.0) {
        var285 = 0.01103139;
    } else {
        var285 = -0.008609681;
    }
    double var286;
    if (input[10] >= 9.262344) {
        var286 = 0.007606411;
    } else {
        var286 = -0.007922391;
    }
    double var287;
    if (input[3] >= -45.0) {
        var287 = 0.0024338753;
    } else {
        var287 = -0.00749514;
    }
    double var288;
    if (input[3] >= -45.0) {
        var288 = 0.0053605875;
    } else {
        var288 = -0.00790353;
    }
    double var289;
    if (input[10] >= 9.309687) {
        var289 = 0.0039675217;
    } else {
        var289 = -0.00681721;
    }
    double var290;
    if (input[1] >= 24.9648) {
        var290 = 0.003524074;
    } else {
        var290 = -0.0077467607;
    }
    double var291;
    if (input[3] >= -45.0) {
        var291 = 0.0053480174;
    } else {
        var291 = -0.007589833;
    }
    double var292;
    if (input[3] >= -45.0) {
        var292 = 0.0057941806;
    } else {
        var292 = -0.008683882;
    }
    double var293;
    if (input[3] >= -45.0) {
        var293 = 0.0050343145;
    } else {
        var293 = -0.007222471;
    }
    double var294;
    if (input[3] >= -45.0) {
        var294 = 0.0050390675;
    } else {
        var294 = -0.0071136295;
    }
    double var295;
    if (input[1] >= 23.618301) {
        var295 = -0.00029974102;
    } else {
        var295 = -0.0056124907;
    }
    double var296;
    if (input[10] >= 9.362873) {
        var296 = 0.002420198;
    } else {
        var296 = -0.0059093996;
    }
    double var297;
    if (input[3] >= -45.0) {
        var297 = 0.005033343;
    } else {
        var297 = -0.0075815865;
    }
    double var298;
    if (input[10] >= 9.327923) {
        var298 = 0.00398742;
    } else {
        var298 = -0.0062202276;
    }
    double var299;
    if (input[3] >= -45.0) {
        var299 = 0.0053943843;
    } else {
        var299 = -0.0067242347;
    }
    double var300;
    if (input[1] >= 25.12215) {
        var300 = 0.0033240037;
    } else {
        var300 = -0.0046354276;
    }
    double var301;
    if (input[1] >= 22.84755) {
        var301 = 0.0034694236;
    } else {
        var301 = -0.0057353363;
    }
    double var302;
    if (input[7] >= 699.9286) {
        var302 = -0.004967009;
    } else {
        var302 = 0.0025401432;
    }
    double var303;
    if (input[3] >= -45.0) {
        var303 = 0.0047734096;
    } else {
        var303 = -0.0071023107;
    }
    double var304;
    if (input[1] >= 22.80935) {
        var304 = 0.006373348;
    } else {
        var304 = -0.0044406313;
    }
    double var305;
    if (input[1] >= 25.12215) {
        var305 = 0.0030493827;
    } else {
        var305 = -0.006152347;
    }
    double var306;
    if (input[1] >= 23.0122) {
        var306 = 0.0034440067;
    } else {
        var306 = -0.0042843535;
    }
    double var307;
    if (input[3] >= -45.0) {
        var307 = 0.0052081603;
    } else {
        var307 = -0.007961812;
    }
    double var308;
    if (input[3] >= -45.0) {
        var308 = 0.005274747;
    } else {
        var308 = -0.007451724;
    }
    double var309;
    if (input[3] >= -45.0) {
        var309 = 0.004886543;
    } else {
        var309 = -0.007477981;
    }
    double var310;
    if (input[10] >= 9.397614) {
        var310 = 0.0021426426;
    } else {
        var310 = -0.004923794;
    }
    double var311;
    if (input[1] >= 23.39575) {
        var311 = 0.0024710556;
    } else {
        var311 = -0.0051118433;
    }
    double var312;
    if (input[1] >= 23.618301) {
        var312 = 0.0022457077;
    } else {
        var312 = -0.005499426;
    }
    double var313;
    if (input[1] >= 23.618301) {
        var313 = 0.0014424747;
    } else {
        var313 = -0.0047709784;
    }
    double var314;
    if (input[7] >= 623.40576) {
        var314 = -0.0043553393;
    } else {
        var314 = 0.0029456592;
    }
    double var315;
    if (input[10] >= 9.390556) {
        var315 = 0.0025703881;
    } else {
        var315 = -0.004713722;
    }
    double var316;
    if (input[3] >= -45.0) {
        var316 = 0.005713997;
    } else {
        var316 = -0.00767151;
    }
    double var317;
    if (input[7] >= 579.5327) {
        var317 = -0.0035357454;
    } else {
        var317 = 0.00566133;
    }
    double var318;
    if (input[1] >= 25.14315) {
        var318 = 0.0019032415;
    } else {
        var318 = -0.0037204374;
    }
    double var319;
    if (input[1] >= 25.14315) {
        var319 = 0.0018373721;
    } else {
        var319 = -0.004164929;
    }
    double var320;
    if (input[3] >= -45.0) {
        var320 = 0.0047290833;
    } else {
        var320 = -0.0075683123;
    }
    double var321;
    if (input[3] >= -45.0) {
        var321 = 0.0048779296;
    } else {
        var321 = -0.0071568596;
    }
    double var322;
    if (input[3] >= -45.0) {
        var322 = 0.0050015026;
    } else {
        var322 = -0.007182296;
    }
    double var323;
    if (input[3] >= -45.0) {
        var323 = 0.0044382005;
    } else {
        var323 = -0.0065796073;
    }
    double var324;
    if (input[3] >= -45.0) {
        var324 = 0.004564998;
    } else {
        var324 = -0.0067460807;
    }
    double var325;
    if (input[10] >= 9.416645) {
        var325 = 0.0024120172;
    } else {
        var325 = -0.0034946797;
    }
    double var326;
    if (input[1] >= 24.9648) {
        var326 = 0.0024717187;
    } else {
        var326 = -0.0038360306;
    }
    double var327;
    if (input[1] >= 25.107399) {
        var327 = 0.0023351659;
    } else {
        var327 = -0.0029119423;
    }
    double var328;
    if (input[1] >= 23.8674) {
        var328 = 0.0031638637;
    } else {
        var328 = -0.0023397992;
    }
    double var329;
    if (input[1] >= 25.107399) {
        var329 = 0.002846406;
    } else {
        var329 = -0.0029762923;
    }
    double var330;
    if (input[1] >= 25.14315) {
        var330 = 0.0025302111;
    } else {
        var330 = -0.004280546;
    }
    double var331;
    if (input[10] >= 9.427293) {
        var331 = 0.0033098103;
    } else {
        var331 = -0.0034279805;
    }
    double var332;
    if (input[4] >= 23.5) {
        var332 = 0.0019556035;
    } else {
        var332 = -0.003413877;
    }
    double var333;
    if (input[10] >= 9.416645) {
        var333 = 0.003097748;
    } else {
        var333 = -0.0037892608;
    }
    double var334;
    if (input[1] >= 24.77375) {
        var334 = 0.002647176;
    } else {
        var334 = -0.0032119553;
    }
    double var335;
    if (input[1] >= 25.14315) {
        var335 = 0.0024788491;
    } else {
        var335 = -0.0037266647;
    }
    double var336;
    if (input[10] >= 9.445118) {
        var336 = 0.0023335;
    } else {
        var336 = -0.0031178524;
    }
    double var337;
    if (input[10] >= 9.4312935) {
        var337 = 0.0019401141;
    } else {
        var337 = -0.0031210487;
    }
    double var338;
    if (input[1] >= 24.634949) {
        var338 = 0.002471095;
    } else {
        var338 = -0.002980746;
    }
    double var339;
    if (input[1] >= 25.5903) {
        var339 = 0.0022054936;
    } else {
        var339 = -0.0028116896;
    }
    double var340;
    if (input[1] >= 25.12215) {
        var340 = 0.0023103124;
    } else {
        var340 = -0.002321413;
    }
    double var341;
    if (input[1] >= 24.9648) {
        var341 = 0.0020910448;
    } else {
        var341 = -0.0039267833;
    }
    double var342;
    if (input[1] >= 25.5903) {
        var342 = 0.002458146;
    } else {
        var342 = -0.0032170468;
    }
    double var343;
    if (input[1] >= 24.701199) {
        var343 = 0.0013597913;
    } else {
        var343 = -0.0020823514;
    }
    double var344;
    if (input[1] >= 24.453499) {
        var344 = 0.0013459709;
    } else {
        var344 = -0.0024725748;
    }
    double var345;
    if (input[1] >= 24.4435) {
        var345 = 0.0013165133;
    } else {
        var345 = -0.0022988198;
    }
    double var346;
    if (input[10] >= 9.484518) {
        var346 = 0.001285644;
    } else {
        var346 = -0.002000407;
    }
    double var347;
    if (input[1] >= 24.9648) {
        var347 = 0.0015485969;
    } else {
        var347 = -0.001979638;
    }
    double var348;
    if (input[1] >= 23.39575) {
        var348 = 0.0017099282;
    } else {
        var348 = -0.0020728756;
    }
    double var349;
    if (input[10] >= 9.489467) {
        var349 = 0.0018986868;
    } else {
        var349 = -0.0018746433;
    }
    double var350;
    if (input[5] >= 0.0521115) {
        var350 = -0.0008317711;
    } else {
        var350 = 0.00030494193;
    }
    double var351;
    if (input[1] >= 24.9648) {
        var351 = 0.0014541388;
    } else {
        var351 = -0.0026425968;
    }
    double var352;
    if (input[1] >= 25.177952) {
        var352 = 0.0019131713;
    } else {
        var352 = -0.0021441372;
    }
    double var353;
    if (input[0] >= -56.46) {
        var353 = 0.0010708475;
    } else {
        var353 = -0.0019906983;
    }
    double var354;
    if (input[10] >= 9.489467) {
        var354 = 0.0014400496;
    } else {
        var354 = -0.0011847336;
    }
    double var355;
    if (input[0] >= -56.495003) {
        var355 = 0.0007362464;
    } else {
        var355 = -0.00140141;
    }
    double var356;
    if (input[5] >= 0.086739) {
        if (input[5] >= 0.221778) {
            var356 = -0.0321267;
        } else {
            if (input[10] >= 8.177676) {
                var356 = 0.096734695;
            } else {
                var356 = 0.03846154;
            }
        }
    } else {
        var356 = -0.032793522;
    }
    double var357;
    if (input[10] >= 9.169266) {
        var357 = -0.032448333;
    } else {
        if (input[10] >= 7.9137745) {
            var357 = 0.08749525;
        } else {
            var357 = -0.03176776;
        }
    }
    double var358;
    if (input[10] >= 9.169266) {
        var358 = -0.03208677;
    } else {
        if (input[10] >= 7.9108906) {
            var358 = 0.07955984;
        } else {
            var358 = -0.031394474;
        }
    }
    double var359;
    if (input[10] >= 9.169266) {
        var359 = -0.031742033;
    } else {
        if (input[5] >= 0.22475949) {
            var359 = -0.031106172;
        } else {
            var359 = 0.073716246;
        }
    }
    double var360;
    if (input[10] >= 9.169266) {
        var360 = -0.031364337;
    } else {
        if (input[10] >= 7.7691007) {
            var360 = 0.06806908;
        } else {
            var360 = -0.03074495;
        }
    }
    double var361;
    if (input[10] >= 9.169266) {
        var361 = -0.031099353;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[5] >= 0.18366) {
                var361 = 0.028726134;
            } else {
                var361 = 0.066000216;
            }
        } else {
            var361 = -0.03039817;
        }
    }
    double var362;
    if (input[10] >= 9.169266) {
        var362 = -0.03074429;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[5] >= 0.18366) {
                var362 = 0.021581756;
            } else {
                var362 = 0.061232027;
            }
        } else {
            var362 = -0.030113405;
        }
    }
    double var363;
    if (input[10] >= 9.169266) {
        var363 = -0.0304487;
    } else {
        if (input[10] >= 7.7691007) {
            var363 = 0.05674807;
        } else {
            var363 = -0.029757729;
        }
    }
    double var364;
    if (input[6] >= 109.59596) {
        if (input[6] >= 128.78787) {
            var364 = -0.029523332;
        } else {
            var364 = 0.055539776;
        }
    } else {
        var364 = -0.030231778;
    }
    double var365;
    if (input[10] >= 9.169266) {
        var365 = -0.029882414;
    } else {
        if (input[6] >= 128.78787) {
            var365 = -0.029198175;
        } else {
            var365 = 0.05178708;
        }
    }
    double var366;
    if (input[6] >= 110.10101) {
        if (input[6] >= 128.78787) {
            var366 = -0.028759165;
        } else {
            var366 = 0.04990706;
        }
    } else {
        if (input[0] >= -52.21) {
            var366 = -0.0057703573;
        } else {
            var366 = -0.029688189;
        }
    }
    double var367;
    if (input[5] >= 0.086739) {
        if (input[5] >= 0.221778) {
            var367 = -0.028638044;
        } else {
            var367 = 0.04775915;
        }
    } else {
        if (input[0] >= -52.235) {
            var367 = -0.0054291724;
        } else {
            var367 = -0.029450048;
        }
    }
    double var368;
    if (input[5] >= 0.086739) {
        if (input[5] >= 0.22475949) {
            var368 = -0.028273044;
        } else {
            var368 = 0.04586484;
        }
    } else {
        if (input[0] >= -52.34) {
            var368 = -0.005096049;
        } else {
            var368 = -0.029135196;
        }
    }
    double var369;
    if (input[10] >= 9.169266) {
        var369 = -0.028879082;
    } else {
        if (input[10] >= 7.7691007) {
            var369 = 0.04396319;
        } else {
            var369 = -0.028056964;
        }
    }
    double var370;
    if (input[10] >= 9.169266) {
        var370 = -0.02861075;
    } else {
        if (input[10] >= 7.7691007) {
            var370 = 0.04331785;
        } else {
            var370 = -0.027871922;
        }
    }
    double var371;
    if (input[10] >= 9.169266) {
        var371 = -0.028444279;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[10] >= 8.14498) {
                var371 = 0.04244735;
            } else {
                var371 = 0.020341517;
            }
        } else {
            var371 = -0.027789116;
        }
    }
    double var372;
    if (input[10] >= 9.169266) {
        var372 = -0.028279293;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[10] >= 8.14498) {
                var372 = 0.04107667;
            } else {
                var372 = 0.019720763;
            }
        } else {
            var372 = -0.027380899;
        }
    }
    double var373;
    if (input[10] >= 9.169266) {
        var373 = -0.028040616;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[1] >= 13.14835) {
                var373 = 0.040531516;
            } else {
                if (input[1] >= 11.66115) {
                    var373 = 0.004664162;
                } else {
                    var373 = 0.03247842;
                }
            }
        } else {
            var373 = -0.027239094;
        }
    }
    double var374;
    if (input[10] >= 9.169266) {
        var374 = -0.027916897;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[10] >= 8.14498) {
                var374 = 0.03885479;
            } else {
                var374 = 0.018075537;
            }
        } else {
            var374 = -0.026996924;
        }
    }
    double var375;
    if (input[6] >= 109.59596) {
        if (input[6] >= 128.78787) {
            var375 = -0.026795805;
        } else {
            var375 = 0.038933925;
        }
    } else {
        var375 = -0.027784495;
    }
    double var376;
    if (input[10] >= 9.169266) {
        var376 = -0.02743555;
    } else {
        if (input[5] >= 0.22475949) {
            var376 = -0.026417524;
        } else {
            if (input[1] >= 13.48835) {
                var376 = 0.037544545;
            } else {
                if (input[1] >= 11.66115) {
                    var376 = 0.0023756952;
                } else {
                    var376 = 0.030895581;
                }
            }
        }
    }
    double var377;
    if (input[10] >= 9.169266) {
        var377 = -0.027306994;
    } else {
        if (input[10] >= 7.9108906) {
            if (input[10] >= 8.177676) {
                var377 = 0.036079463;
            } else {
                var377 = 0.014722901;
            }
        } else {
            var377 = -0.026676623;
        }
    }
    double var378;
    if (input[5] >= 0.086739) {
        if (input[5] >= 0.22475949) {
            var378 = -0.026193038;
        } else {
            if (input[1] >= 13.14835) {
                var378 = 0.03643899;
            } else {
                if (input[1] >= 11.66115) {
                    var378 = 0.0014215326;
                } else {
                    var378 = 0.030107737;
                }
            }
        }
    } else {
        if (input[0] >= -53.29) {
            var378 = -0.0046276622;
        } else {
            var378 = -0.027040584;
        }
    }
    double var379;
    if (input[10] >= 9.169266) {
        var379 = -0.0269448;
    } else {
        if (input[10] >= 7.9108906) {
            var379 = 0.033965275;
        } else {
            var379 = -0.026304454;
        }
    }
    double var380;
    if (input[10] >= 9.169266) {
        var380 = -0.026819373;
    } else {
        if (input[10] >= 7.738643) {
            if (input[5] >= 0.18366) {
                var380 = 0.016977761;
            } else {
                var380 = 0.033930376;
            }
        } else {
            var380 = -0.025726227;
        }
    }
    double var381;
    if (input[10] >= 9.169266) {
        var381 = -0.026683992;
    } else {
        if (input[5] >= 0.221778) {
            var381 = -0.025661651;
        } else {
            if (input[10] >= 8.14498) {
                var381 = 0.033405963;
            } else {
                var381 = 0.01642361;
            }
        }
    }
    double var382;
    if (input[10] >= 9.169266) {
        var382 = -0.026512155;
    } else {
        if (input[5] >= 0.221778) {
            var382 = -0.025248636;
        } else {
            var382 = 0.033473253;
        }
    }
    double var383;
    if (input[10] >= 9.169266) {
        var383 = -0.026301969;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[1] >= 13.14835) {
                var383 = 0.032726396;
            } else {
                if (input[1] >= 11.859501) {
                    var383 = -0.0021481307;
                } else {
                    var383 = 0.026402066;
                }
            }
        } else {
            var383 = -0.025225554;
        }
    }
    double var384;
    if (input[10] >= 9.169266) {
        var384 = -0.026234215;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[10] >= 8.14498) {
                var384 = 0.032702826;
            } else {
                var384 = 0.011932648;
            }
        } else {
            var384 = -0.025017424;
        }
    }
    double var385;
    if (input[10] >= 9.169266) {
        var385 = -0.026042594;
    } else {
        if (input[5] >= 0.221778) {
            var385 = -0.024835465;
        } else {
            if (input[1] >= 13.14835) {
                var385 = 0.03291499;
            } else {
                if (input[1] >= 11.63475) {
                    var385 = -0.0032366018;
                } else {
                    var385 = 0.025991613;
                }
            }
        }
    }
    double var386;
    if (input[5] >= 0.086739) {
        if (input[5] >= 0.221778) {
            var386 = -0.024588548;
        } else {
            if (input[10] >= 8.14498) {
                var386 = 0.031349797;
            } else {
                var386 = 0.013364837;
            }
        }
    } else {
        var386 = -0.026230184;
    }
    double var387;
    if (input[10] >= 9.169266) {
        var387 = -0.025812164;
    } else {
        if (input[10] >= 7.7691007) {
            var387 = 0.031187816;
        } else {
            var387 = -0.024424598;
        }
    }
    double var388;
    if (input[5] >= 0.086739) {
        if (input[5] >= 0.221778) {
            var388 = -0.02439719;
        } else {
            if (input[1] >= 13.14835) {
                var388 = 0.031040693;
            } else {
                if (input[5] >= 0.156103) {
                    var388 = -0.0043690265;
                } else {
                    var388 = 0.024210248;
                }
            }
        }
    } else {
        if (input[3] >= -43.0) {
            var388 = -0.004841286;
        } else {
            var388 = -0.025815351;
        }
    }
    double var389;
    if (input[5] >= 0.086739) {
        if (input[5] >= 0.221778) {
            var389 = -0.023905104;
        } else {
            if (input[1] >= 13.14835) {
                var389 = 0.030690173;
            } else {
                if (input[5] >= 0.1489205) {
                    var389 = -0.0047383746;
                } else {
                    var389 = 0.022215037;
                }
            }
        }
    } else {
        var389 = -0.025782451;
    }
    double var390;
    if (input[10] >= 9.169266) {
        var390 = -0.025452122;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[4] >= 16.5) {
                var390 = 0.029861817;
            } else {
                var390 = 0.0084374705;
            }
        } else {
            var390 = -0.023834568;
        }
    }
    double var391;
    if (input[10] >= 9.169266) {
        var391 = -0.025278766;
    } else {
        if (input[10] >= 7.9108906) {
            if (input[10] >= 8.14498) {
                var391 = 0.02897707;
            } else {
                var391 = 0.008188813;
            }
        } else {
            var391 = -0.024594007;
        }
    }
    double var392;
    if (input[10] >= 9.169266) {
        var392 = -0.025120273;
    } else {
        if (input[10] >= 7.9108906) {
            if (input[10] >= 8.14498) {
                var392 = 0.02847389;
            } else {
                var392 = 0.007833795;
            }
        } else {
            var392 = -0.0244095;
        }
    }
    double var393;
    if (input[10] >= 9.169266) {
        var393 = -0.025062859;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[1] >= 13.8971) {
                var393 = 0.028768698;
            } else {
                if (input[3] >= -43.0) {
                    var393 = 0.023017539;
                } else {
                    var393 = -0.004486038;
                }
            }
        } else {
            var393 = -0.023602625;
        }
    }
    double var394;
    if (input[10] >= 9.169266) {
        var394 = -0.02491022;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[1] >= 13.14835) {
                var394 = 0.028372005;
            } else {
                if (input[1] >= 11.566) {
                    var394 = -0.0047307643;
                } else {
                    var394 = 0.02121997;
                }
            }
        } else {
            var394 = -0.023309859;
        }
    }
    double var395;
    if (input[5] >= 0.086739) {
        if (input[5] >= 0.221778) {
            var395 = -0.023214718;
        } else {
            if (input[1] >= 13.14835) {
                var395 = 0.028942347;
            } else {
                if (input[2] >= -59.0) {
                    var395 = 0.021021858;
                } else {
                    var395 = -0.005000863;
                }
            }
        }
    } else {
        if (input[0] >= -53.86) {
            var395 = -0.0039491733;
        } else {
            var395 = -0.0250195;
        }
    }
    double var396;
    if (input[10] >= 9.169266) {
        var396 = -0.024655573;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[10] >= 8.14498) {
                var396 = 0.027177224;
            } else {
                var396 = 0.009385545;
            }
        } else {
            var396 = -0.023083095;
        }
    }
    double var397;
    if (input[10] >= 9.185728) {
        var397 = -0.02458364;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[1] >= 13.14835) {
                var397 = 0.02764527;
            } else {
                var397 = 0.008599172;
            }
        } else {
            var397 = -0.023021957;
        }
    }
    double var398;
    if (input[10] >= 9.169266) {
        var398 = -0.024483867;
    } else {
        if (input[10] >= 8.150295) {
            var398 = 0.026728297;
        } else {
            if (input[10] >= 7.7700176) {
                var398 = -0.004922343;
            } else {
                var398 = -0.022569126;
            }
        }
    }
    double var399;
    if (input[10] >= 9.169266) {
        var399 = -0.024394294;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[0] >= -49.975) {
                var399 = 0.011580671;
            } else {
                var399 = 0.027190119;
            }
        } else {
            var399 = -0.022387965;
        }
    }
    double var400;
    if (input[10] >= 9.169266) {
        var400 = -0.024222324;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[2] >= -60.0) {
                var400 = 0.008272048;
            } else {
                var400 = 0.026724547;
            }
        } else {
            var400 = -0.022177609;
        }
    }
    double var401;
    if (input[10] >= 9.169266) {
        var401 = -0.024120992;
    } else {
        if (input[10] >= 7.9108906) {
            if (input[4] >= 16.5) {
                var401 = 0.026114494;
            } else {
                var401 = 0.0061233765;
            }
        } else {
            var401 = -0.023201326;
        }
    }
    double var402;
    if (input[5] >= 0.086739) {
        if (input[10] >= 8.14498) {
            var402 = 0.026613394;
        } else {
            if (input[1] >= 25.1147) {
                var402 = 0.007852683;
            } else {
                var402 = -0.022824584;
            }
        }
    } else {
        var402 = -0.024606103;
    }
    double var403;
    if (input[5] >= 0.0697475) {
        if (input[5] >= 0.221778) {
            var403 = -0.0213419;
        } else {
            if (input[1] >= 13.14835) {
                if (input[7] >= 1351.9028) {
                    var403 = 0.02711643;
                } else {
                    var403 = 0.005422028;
                }
            } else {
                var403 = 0.0037533646;
            }
        }
    } else {
        var403 = -0.023696197;
    }
    double var404;
    if (input[10] >= 9.169266) {
        var404 = -0.023749491;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[1] >= 13.8971) {
                var404 = 0.026045693;
            } else {
                var404 = 0.0074693034;
            }
        } else {
            var404 = -0.021877361;
        }
    }
    double var405;
    if (input[10] >= 9.169266) {
        var405 = -0.023719365;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[1] >= 13.14835) {
                var405 = 0.025846401;
            } else {
                var405 = 0.0072272653;
            }
        } else {
            var405 = -0.021440059;
        }
    }
    double var406;
    if (input[10] >= 9.169266) {
        var406 = -0.02357711;
    } else {
        if (input[10] >= 8.14498) {
            var406 = 0.026718725;
        } else {
            if (input[4] >= 19.5) {
                var406 = 0.0006785634;
            } else {
                var406 = -0.026533177;
            }
        }
    }
    double var407;
    if (input[10] >= 9.169266) {
        var407 = -0.023449555;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[1] >= 13.14835) {
                var407 = 0.025379708;
            } else {
                var407 = 0.0017394827;
            }
        } else {
            var407 = -0.021335235;
        }
    }
    double var408;
    if (input[6] >= 109.59596) {
        if (input[6] >= 128.78787) {
            var408 = -0.020670129;
        } else {
            if (input[1] >= 13.14835) {
                var408 = 0.026094958;
            } else {
                var408 = 0.0042590387;
            }
        }
    } else {
        var408 = -0.024069432;
    }
    double var409;
    if (input[10] >= 9.169266) {
        var409 = -0.023141671;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[1] >= 13.14835) {
                var409 = 0.024898198;
            } else {
                var409 = 0.0026012154;
            }
        } else {
            var409 = -0.020929346;
        }
    }
    double var410;
    if (input[10] >= 9.169266) {
        var410 = -0.023013836;
    } else {
        if (input[5] >= 0.221778) {
            var410 = -0.020231506;
        } else {
            if (input[0] >= -50.845) {
                var410 = 0.008542822;
            } else {
                var410 = 0.024761671;
            }
        }
    }
    double var411;
    if (input[10] >= 9.169266) {
        var411 = -0.02290956;
    } else {
        if (input[10] >= 8.14498) {
            var411 = 0.023812113;
        } else {
            if (input[1] >= 16.1847) {
                var411 = 0.0021560672;
            } else {
                var411 = -0.026541067;
            }
        }
    }
    double var412;
    if (input[5] >= 0.086739) {
        if (input[5] >= 0.221778) {
            var412 = -0.020301787;
        } else {
            if (input[1] >= 13.14835) {
                var412 = 0.02558433;
            } else {
                var412 = 0.00401584;
            }
        }
    } else {
        if (input[0] >= -54.695) {
            var412 = -0.004535357;
        } else {
            var412 = -0.023164852;
        }
    }
    double var413;
    if (input[10] >= 9.169266) {
        var413 = -0.02260086;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[5] >= 0.18366) {
                var413 = 0.0031915556;
            } else {
                var413 = 0.025720537;
            }
        } else {
            var413 = -0.020092664;
        }
    }
    double var414;
    if (input[5] >= 0.0697475) {
        if (input[5] >= 0.18366) {
            if (input[4] >= 21.5) {
                var414 = 0.0061720214;
            } else {
                var414 = -0.020966742;
            }
        } else {
            var414 = 0.023247499;
        }
    } else {
        var414 = -0.022357654;
    }
    double var415;
    if (input[10] >= 9.169266) {
        var415 = -0.02227752;
    } else {
        if (input[10] >= 8.150295) {
            var415 = 0.025380874;
        } else {
            if (input[4] >= 19.5) {
                var415 = 0.002544237;
            } else {
                var415 = -0.020417992;
            }
        }
    }
    double var416;
    if (input[10] >= 9.169266) {
        var416 = -0.022426244;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[1] >= 13.14835) {
                var416 = 0.023679178;
            } else {
                var416 = 0.0014069703;
            }
        } else {
            var416 = -0.019519625;
        }
    }
    double var417;
    if (input[10] >= 9.169266) {
        var417 = -0.022108732;
    } else {
        if (input[10] >= 7.7266526) {
            if (input[1] >= 13.14835) {
                var417 = 0.02357004;
            } else {
                var417 = 0.0014068116;
            }
        } else {
            var417 = -0.019244902;
        }
    }
    double var418;
    if (input[10] >= 9.169266) {
        var418 = -0.02217649;
    } else {
        if (input[10] >= 8.14498) {
            if (input[4] >= 26.5) {
                var418 = 0.010390623;
            } else {
                var418 = 0.024788165;
            }
        } else {
            if (input[4] >= 19.5) {
                var418 = 0.004144182;
            } else {
                var418 = -0.0262776;
            }
        }
    }
    double var419;
    if (input[5] >= 0.0697475) {
        if (input[5] >= 0.221778) {
            var419 = -0.018770387;
        } else {
            if (input[1] >= 13.14835) {
                if (input[7] >= 1450.8723) {
                    var419 = 0.024618393;
                } else {
                    var419 = 0.005433;
                }
            } else {
                var419 = -0.00064013276;
            }
        }
    } else {
        var419 = -0.021692162;
    }
    double var420;
    if (input[10] >= 9.169266) {
        var420 = -0.021826137;
    } else {
        if (input[10] >= 8.14498) {
            if (input[4] >= 26.5) {
                var420 = 0.009783172;
            } else {
                var420 = 0.024275267;
            }
        } else {
            if (input[1] >= 16.1847) {
                var420 = 0.0056778444;
            } else {
                var420 = -0.02607418;
            }
        }
    }
    double var421;
    if (input[10] >= 9.194216) {
        var421 = -0.021595355;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[1] >= 13.14835) {
                if (input[4] >= 26.5) {
                    var421 = 0.010396645;
                } else {
                    var421 = 0.025444115;
                }
            } else {
                var421 = 0.0044358545;
            }
        } else {
            var421 = -0.018822154;
        }
    }
    double var422;
    if (input[10] >= 9.169266) {
        var422 = -0.021395212;
    } else {
        if (input[10] >= 7.7691007) {
            if (input[1] >= 13.14835) {
                if (input[4] >= 26.5) {
                    var422 = 0.009078;
                } else {
                    var422 = 0.025290117;
                }
            } else {
                var422 = 0.0011398944;
            }
        } else {
            var422 = -0.018275145;
        }
    }
    double var423;
    if (input[10] >= 9.185728) {
        var423 = -0.021339467;
    } else {
        if (input[10] >= 8.14498) {
            var423 = 0.024373917;
        } else {
            if (input[1] >= 16.1847) {
                var423 = 0.0019325819;
            } else {
                var423 = -0.019008547;
            }
        }
    }
    double var424;
    if (input[5] >= 0.086739) {
        if (input[10] >= 8.14498) {
            var424 = 0.023026882;
        } else {
            if (input[2] >= -64.0) {
                var424 = -0.018664742;
            } else {
                var424 = -0.0015105233;
            }
        }
    } else {
        var424 = -0.022296313;
    }
    double var425;
    if (input[10] >= 9.169266) {
        var425 = -0.021027459;
    } else {
        if (input[10] >= 7.738643) {
            if (input[1] >= 13.14835) {
                var425 = 0.022132188;
            } else {
                var425 = 0.00042435774;
            }
        } else {
            var425 = -0.017676754;
        }
    }
    double var426;
    if (input[10] >= 9.169266) {
        var426 = -0.020843752;
    } else {
        if (input[10] >= 8.14498) {
            if (input[0] >= -56.885002) {
                var426 = 0.023550777;
            } else {
                var426 = 0.008920101;
            }
        } else {
            if (input[1] >= 16.1847) {
                var426 = 0.0025777307;
            } else {
                var426 = -0.018240191;
            }
        }
    }
    double var427;
    if (input[10] >= 9.169266) {
        var427 = -0.020682303;
    } else {
        if (input[10] >= 7.738643) {
            if (input[1] >= 13.14835) {
                if (input[4] >= 26.5) {
                    var427 = 0.009753355;
                } else {
                    var427 = 0.02481878;
                }
            } else {
                var427 = 0.0007950156;
            }
        } else {
            var427 = -0.017606806;
        }
    }
    double var428;
    if (input[10] >= 9.169266) {
        var428 = -0.020495716;
    } else {
        if (input[10] >= 7.7691007) {
            var428 = 0.02239232;
        } else {
            var428 = -0.017496267;
        }
    }
    double var429;
    if (input[10] >= 9.169266) {
        var429 = -0.020174649;
    } else {
        if (input[5] >= 0.209375) {
            var429 = -0.011802348;
        } else {
            if (input[0] >= -53.625) {
                var429 = 0.023586174;
            } else {
                if (input[3] >= -46.0) {
                    var429 = -0.007249638;
                } else {
                    var429 = 0.019093405;
                }
            }
        }
    }
    double var430;
    if (input[5] >= 0.0697475) {
        if (input[5] >= 0.209375) {
            var430 = -0.0072599687;
        } else {
            var430 = 0.022209903;
        }
    } else {
        var430 = -0.01991288;
    }
    double var431;
    if (input[10] >= 9.169266) {
        var431 = -0.019965876;
    } else {
        if (input[10] >= 8.14498) {
            if (input[0] >= -56.85) {
                var431 = 0.022804236;
            } else {
                var431 = 0.007702446;
            }
        } else {
            if (input[1] >= 16.1847) {
                var431 = 0.0058209104;
            } else {
                var431 = -0.018240822;
            }
        }
    }
    double var432;
    if (input[10] >= 9.169266) {
        var432 = -0.019969648;
    } else {
        if (input[7] >= 2573.2068) {
            var432 = -0.010108442;
        } else {
            if (input[1] >= 30.96015) {
                var432 = 0.008098864;
            } else {
                var432 = 0.022995064;
            }
        }
    }
    double var433;
    if (input[5] >= 0.0697475) {
        if (input[7] >= 2576.2676) {
            var433 = -0.007930561;
        } else {
            var433 = 0.022254767;
        }
    } else {
        var433 = -0.019403951;
    }
    double var434;
    if (input[10] >= 9.169266) {
        var434 = -0.019708969;
    } else {
        if (input[10] >= 7.9108906) {
            if (input[0] >= -53.625) {
                var434 = 0.023081325;
            } else {
                if (input[1] >= 27.8563) {
                    var434 = 0.009410264;
                } else {
                    var434 = 0.0025739965;
                }
            }
        } else {
            var434 = -0.018554414;
        }
    }
    double var435;
    if (input[5] >= 0.0697475) {
        if (input[5] >= 0.18366) {
            if (input[1] >= 16.082699) {
                var435 = 0.0055796923;
            } else {
                var435 = -0.017332792;
            }
        } else {
            if (input[7] >= 1529.4358) {
                var435 = 0.020090185;
            } else {
                var435 = 0.0045506605;
            }
        }
    } else {
        var435 = -0.019152245;
    }
    double var436;
    if (input[10] >= 9.185728) {
        var436 = -0.019449322;
    } else {
        if (input[10] >= 8.14498) {
            if (input[0] >= -56.72) {
                var436 = 0.022109402;
            } else {
                var436 = 0.0077835135;
            }
        } else {
            var436 = -0.009445419;
        }
    }
    double var437;
    if (input[10] >= 9.169266) {
        var437 = -0.019015636;
    } else {
        if (input[10] >= 8.14498) {
            var437 = 0.022885593;
        } else {
            if (input[4] >= 19.5) {
                var437 = 0.007383205;
            } else {
                var437 = -0.017502459;
            }
        }
    }
    double var438;
    if (input[10] >= 9.169266) {
        var438 = -0.018757066;
    } else {
        if (input[10] >= 8.14498) {
            if (input[1] >= 28.809551) {
                var438 = 0.007919805;
            } else {
                var438 = 0.021551691;
            }
        } else {
            if (input[4] >= 19.5) {
                var438 = 0.007983203;
            } else {
                var438 = -0.017007725;
            }
        }
    }
    double var439;
    if (input[5] >= 0.0697475) {
        if (input[5] >= 0.18366) {
            var439 = -0.0054099914;
        } else {
            if (input[4] >= 23.5) {
                var439 = 0.005716424;
            } else {
                var439 = 0.019740762;
            }
        }
    } else {
        var439 = -0.018586798;
    }
    double var440;
    if (input[10] >= 9.169266) {
        var440 = -0.018993525;
    } else {
        if (input[10] >= 8.14498) {
            if (input[4] >= 23.5) {
                var440 = 0.008247288;
            } else {
                var440 = 0.02090205;
            }
        } else {
            var440 = -0.0067148106;
        }
    }
    double var441;
    if (input[6] >= 109.59596) {
        if (input[10] >= 8.14498) {
            var441 = 0.020472698;
        } else {
            var441 = -0.004565831;
        }
    } else {
        var441 = -0.018309748;
    }
    double var442;
    if (input[5] >= 0.0697475) {
        if (input[5] >= 0.18366) {
            var442 = -0.005251385;
        } else {
            if (input[4] >= 22.5) {
                var442 = 0.005600666;
            } else {
                var442 = 0.019383993;
            }
        }
    } else {
        var442 = -0.01731216;
    }
    double var443;
    if (input[5] >= 0.0697475) {
        if (input[5] >= 0.209375) {
            var443 = -0.009249492;
        } else {
            if (input[0] >= -53.625) {
                var443 = 0.021988388;
            } else {
                var443 = 0.0028937624;
            }
        }
    } else {
        var443 = -0.017941914;
    }
    double var444;
    if (input[10] >= 9.169266) {
        var444 = -0.018132588;
    } else {
        if (input[10] >= 7.9108906) {
            var444 = 0.02355281;
        } else {
            var444 = -0.009346212;
        }
    }
    double var445;
    if (input[10] >= 9.169266) {
        var445 = -0.017920168;
    } else {
        if (input[10] >= 8.14498) {
            var445 = 0.017592221;
        } else {
            var445 = -0.00501564;
        }
    }
    double var446;
    if (input[10] >= 9.169266) {
        var446 = -0.01769363;
    } else {
        if (input[10] >= 7.9108906) {
            if (input[0] >= -53.625) {
                var446 = 0.02218189;
            } else {
                var446 = 0.0031067473;
            }
        } else {
            var446 = -0.009770026;
        }
    }
    double var447;
    if (input[5] >= 0.086739) {
        if (input[5] >= 0.209375) {
            var447 = -0.009065276;
        } else {
            var447 = 0.022053802;
        }
    } else {
        var447 = -0.013393921;
    }
    double var448;
    if (input[10] >= 9.169266) {
        var448 = -0.017243365;
    } else {
        if (input[10] >= 8.14498) {
            var448 = 0.016044185;
        } else {
            var448 = -0.0049965004;
        }
    }
    double var449;
    if (input[10] >= 9.169266) {
        var449 = -0.01719553;
    } else {
        if (input[10] >= 8.1720295) {
            var449 = 0.015701398;
        } else {
            var449 = -0.005545999;
        }
    }
    double var450;
    if (input[5] >= 0.086739) {
        if (input[5] >= 0.18366) {
            var450 = -0.0049952054;
        } else {
            var450 = 0.019028239;
        }
    } else {
        var450 = -0.012379698;
    }
    double var451;
    if (input[1] >= 20.38035) {
        if (input[5] >= 0.103121) {
            var451 = 0.01626425;
        } else {
            var451 = -0.005393444;
        }
    } else {
        var451 = -0.0077975467;
    }
    double var452;
    if (input[10] >= 9.169266) {
        var452 = -0.016784575;
    } else {
        if (input[7] >= 2576.2676) {
            var452 = -0.009277192;
        } else {
            var452 = 0.01710832;
        }
    }
    double var453;
    if (input[5] >= 0.086739) {
        if (input[7] >= 2835.4248) {
            var453 = 0.00053143443;
        } else {
            var453 = 0.020644993;
        }
    } else {
        var453 = -0.0119171785;
    }
    double var454;
    if (input[5] >= 0.086739) {
        if (input[1] >= 14.98835) {
            var454 = 0.015136495;
        } else {
            var454 = -0.008392519;
        }
    } else {
        var454 = -0.011663869;
    }
    double var455;
    if (input[5] >= 0.086739) {
        if (input[10] >= 8.14498) {
            var455 = 0.01824618;
        } else {
            var455 = -0.0042404192;
        }
    } else {
        var455 = -0.0115755;
    }
    double var456;
    if (input[5] >= 0.086739) {
        if (input[10] >= 8.14498) {
            var456 = 0.018045098;
        } else {
            var456 = -0.0059104715;
        }
    } else {
        var456 = -0.011269237;
    }
    double var457;
    if (input[5] >= 0.086739) {
        if (input[4] >= 18.5) {
            var457 = 0.014206796;
        } else {
            var457 = -0.006800274;
        }
    } else {
        var457 = -0.011461368;
    }
    double var458;
    if (input[5] >= 0.09083401) {
        if (input[10] >= 8.0054455) {
            var458 = 0.019904722;
        } else {
            var458 = -0.0018296068;
        }
    } else {
        var458 = -0.011347593;
    }
    double var459;
    if (input[5] >= 0.09083401) {
        if (input[10] >= 8.14498) {
            var459 = 0.01775384;
        } else {
            var459 = -0.0034336278;
        }
    } else {
        var459 = -0.010381012;
    }
    double var460;
    if (input[4] >= 19.5) {
        if (input[5] >= 0.086739) {
            var460 = 0.014107916;
        } else {
            var460 = -0.009475189;
        }
    } else {
        var460 = -0.013747587;
    }
    double var461;
    if (input[5] >= 0.086739) {
        if (input[10] >= 8.0054455) {
            var461 = 0.01943727;
        } else {
            var461 = -0.0026988932;
        }
    } else {
        var461 = -0.009824893;
    }
    double var462;
    if (input[5] >= 0.086739) {
        if (input[10] >= 8.14498) {
            var462 = 0.017244717;
        } else {
            var462 = -0.0048702727;
        }
    } else {
        var462 = -0.018274223;
    }
    double var463;
    if (input[10] >= 8.902367) {
        var463 = -0.016410407;
    } else {
        if (input[2] >= -64.0) {
            var463 = -0.0067147263;
        } else {
            var463 = 0.013214409;
        }
    }
    double var464;
    if (input[5] >= 0.086739) {
        if (input[4] >= 18.5) {
            var464 = 0.012516794;
        } else {
            var464 = -0.0072151683;
        }
    } else {
        var464 = -0.009654564;
    }
    double var465;
    if (input[5] >= 0.086739) {
        if (input[7] >= 2576.2676) {
            var465 = 0.0052406616;
        } else {
            var465 = 0.019048242;
        }
    } else {
        var465 = -0.009652312;
    }
    double var466;
    if (input[5] >= 0.086739) {
        if (input[1] >= 15.64275) {
            var466 = 0.013474467;
        } else {
            var466 = -0.0075210608;
        }
    } else {
        var466 = -0.009412117;
    }
    double var467;
    if (input[5] >= 0.086739) {
        if (input[1] >= 16.1847) {
            var467 = 0.012973894;
        } else {
            var467 = -0.0066897557;
        }
    } else {
        var467 = -0.009325686;
    }
    double var468;
    if (input[5] >= 0.09083401) {
        if (input[4] >= 18.5) {
            var468 = 0.012662716;
        } else {
            var468 = -0.0063135806;
        }
    } else {
        var468 = -0.009340836;
    }
    double var469;
    if (input[7] >= 1478.4205) {
        if (input[4] >= 21.5) {
            var469 = 0.011654129;
        } else {
            var469 = -0.0059634694;
        }
    } else {
        var469 = -0.013199597;
    }
    double var470;
    if (input[10] >= 8.14498) {
        var470 = 0.006875898;
    } else {
        var470 = -0.0062492485;
    }
    double var471;
    if (input[6] >= 113.63636) {
        if (input[1] >= 16.1847) {
            var471 = 0.011897297;
        } else {
            var471 = -0.007048655;
        }
    } else {
        var471 = -0.014138232;
    }
    double var472;
    if (input[0] >= -52.205) {
        var472 = 0.012830729;
    } else {
        if (input[3] >= -46.0) {
            var472 = -0.0143325105;
        } else {
            var472 = 0.0052023795;
        }
    }
    double var473;
    if (input[5] >= 0.086739) {
        if (input[7] >= 2576.2676) {
            var473 = -0.00636201;
        } else {
            var473 = 0.012342962;
        }
    } else {
        var473 = -0.008730113;
    }
    double var474;
    if (input[0] >= -53.489998) {
        var474 = 0.007212784;
    } else {
        var474 = -0.006484089;
    }
    double var475;
    if (input[0] >= -52.215) {
        var475 = 0.007539134;
    } else {
        if (input[3] >= -46.0) {
            var475 = -0.015385206;
        } else {
            var475 = 0.0056637893;
        }
    }
    double var476;
    if (input[5] >= 0.086739) {
        if (input[10] >= 8.0054455) {
            var476 = 0.018457027;
        } else {
            var476 = -0.00033197747;
        }
    } else {
        var476 = -0.008524164;
    }
    double var477;
    if (input[1] >= 20.336552) {
        if (input[2] >= -70.0) {
            var477 = 0.012296754;
        } else {
            var477 = -0.00380039;
        }
    } else {
        var477 = -0.008449926;
    }
    double var478;
    if (input[0] >= -53.504997) {
        var478 = 0.0065816166;
    } else {
        var478 = -0.006869418;
    }
    double var479;
    if (input[0] >= -53.504997) {
        var479 = 0.0073649413;
    } else {
        var479 = -0.007115525;
    }
    double var480;
    if (input[1] >= 26.2199) {
        var480 = 0.008190454;
    } else {
        var480 = -0.0063623213;
    }
    double var481;
    if (input[4] >= 22.5) {
        var481 = -0.008843198;
    } else {
        var481 = 0.008651554;
    }
    double var482;
    if (input[1] >= 14.98835) {
        if (input[10] >= 8.568251) {
            var482 = 0.0030366816;
        } else {
            var482 = 0.010749186;
        }
    } else {
        var482 = -0.008614512;
    }
    double var483;
    if (input[1] >= 20.38035) {
        var483 = 0.0051427106;
    } else {
        var483 = -0.011764601;
    }
    double var484;
    if (input[0] >= -53.545) {
        var484 = 0.0066617564;
    } else {
        var484 = -0.0069110417;
    }
    double var485;
    if (input[1] >= 20.38035) {
        var485 = 0.0052915327;
    } else {
        var485 = -0.0076306066;
    }
    double var486;
    if (input[0] >= -52.205) {
        var486 = 0.012553415;
    } else {
        if (input[3] >= -46.0) {
            var486 = -0.013699273;
        } else {
            var486 = 0.0051537887;
        }
    }
    double var487;
    if (input[5] >= 0.086739) {
        if (input[5] >= 0.196774) {
            var487 = 0.00116627;
        } else {
            var487 = 0.01756001;
        }
    } else {
        var487 = -0.008817188;
    }
    double var488;
    if (input[7] >= 1553.9231) {
        if (input[1] >= 19.781502) {
            var488 = 0.0121913655;
        } else {
            var488 = -0.006169418;
        }
    } else {
        var488 = -0.011182204;
    }
    double var489;
    if (input[5] >= 0.134183) {
        if (input[10] >= 8.0054455) {
            var489 = 0.0044484264;
        } else {
            var489 = -0.000055168082;
        }
    } else {
        var489 = -0.010648067;
    }
    double var490;
    if (input[0] >= -52.215) {
        var490 = 0.0072272457;
    } else {
        var490 = -0.010637525;
    }
    double var491;
    if (input[0] >= -53.504997) {
        var491 = 0.0063140797;
    } else {
        var491 = -0.0062749805;
    }
    double var492;
    if (input[5] >= 0.086739) {
        if (input[1] >= 20.41035) {
            var492 = 0.011408797;
        } else {
            var492 = -0.0006012368;
        }
    } else {
        var492 = -0.008080553;
    }
    double var493;
    if (input[4] >= 20.5) {
        var493 = 0.006593443;
    } else {
        var493 = -0.007571467;
    }
    double var494;
    if (input[0] >= -51.765) {
        var494 = 0.0081676105;
    } else {
        var494 = -0.006848817;
    }
    double var495;
    if (input[3] >= -45.0) {
        var495 = 0.01249845;
    } else {
        var495 = -0.0013438843;
    }
    double var496;
    if (input[0] >= -53.504997) {
        var496 = 0.010719612;
    } else {
        var496 = -0.006022823;
    }
    double var497;
    if (input[0] >= -53.504997) {
        var497 = 0.0067368746;
    } else {
        var497 = -0.0066267448;
    }
    double var498;
    if (input[2] >= -67.0) {
        var498 = 0.011503338;
    } else {
        var498 = -0.006433149;
    }
    double var499;
    if (input[7] >= 1647.791) {
        var499 = 0.0031389103;
    } else {
        var499 = -0.010101356;
    }
    double var500;
    if (input[0] >= -53.504997) {
        var500 = 0.01012367;
    } else {
        var500 = -0.009878669;
    }
    double var501;
    if (input[0] >= -53.504997) {
        var501 = 0.0068849507;
    } else {
        var501 = -0.005975608;
    }
    double var502;
    if (input[1] >= 20.507149) {
        var502 = 0.0044645583;
    } else {
        var502 = -0.011662884;
    }
    double var503;
    if (input[0] >= -53.489998) {
        var503 = 0.0081686955;
    } else {
        var503 = -0.0064963843;
    }
    double var504;
    if (input[0] >= -52.215) {
        var504 = 0.0077744126;
    } else {
        var504 = -0.0047114487;
    }
    double var505;
    if (input[1] >= 14.4923) {
        if (input[4] >= 22.5) {
            var505 = -0.0040964205;
        } else {
            var505 = 0.012318721;
        }
    } else {
        var505 = -0.006961318;
    }
    double var506;
    if (input[7] >= 1351.9028) {
        if (input[0] >= -52.434998) {
            var506 = 0.0031136987;
        } else {
            var506 = 0.01430552;
        }
    } else {
        var506 = -0.0068565444;
    }
    double var507;
    if (input[0] >= -53.504997) {
        var507 = 0.007255824;
    } else {
        var507 = -0.005774361;
    }
    double var508;
    if (input[0] >= -53.625) {
        var508 = 0.010623131;
    } else {
        var508 = -0.008956371;
    }
    double var509;
    if (input[0] >= -53.504997) {
        var509 = 0.0065239803;
    } else {
        var509 = -0.005563011;
    }
    double var510;
    if (input[1] >= 20.38035) {
        var510 = 0.0054203547;
    } else {
        var510 = -0.012328116;
    }
    double var511;
    if (input[10] >= 8.141666) {
        var511 = -0.0077473405;
    } else {
        var511 = 0.0042110872;
    }
    double var512;
    if (input[4] >= 18.5) {
        if (input[4] >= 22.5) {
            var512 = -0.0040113293;
        } else {
            var512 = 0.0122527545;
        }
    } else {
        var512 = -0.0065011876;
    }
    double var513;
    if (input[1] >= 14.4923) {
        var513 = 0.007274809;
    } else {
        var513 = -0.0070576197;
    }
    double var514;
    if (input[0] >= -52.17) {
        var514 = 0.007434716;
    } else {
        var514 = -0.004725385;
    }
    double var515;
    if (input[0] >= -52.215) {
        var515 = 0.007784135;
    } else {
        var515 = -0.005269361;
    }
    double var516;
    if (input[0] >= -52.205) {
        var516 = 0.007196097;
    } else {
        var516 = -0.005608683;
    }
    double var517;
    if (input[4] >= 19.5) {
        if (input[5] >= 0.134183) {
            var517 = 0.010189052;
        } else {
            var517 = -0.0023477576;
        }
    } else {
        var517 = -0.006388282;
    }
    double var518;
    if (input[0] >= -52.205) {
        var518 = 0.008083944;
    } else {
        var518 = -0.0074543343;
    }
    double var519;
    if (input[0] >= -52.205) {
        var519 = 0.0073683755;
    } else {
        var519 = -0.004483655;
    }
    double var520;
    if (input[0] >= -53.504997) {
        var520 = 0.007394414;
    } else {
        var520 = -0.005488531;
    }
    double var521;
    if (input[10] >= 8.141666) {
        var521 = -0.00608765;
    } else {
        var521 = 0.0037666732;
    }
    double var522;
    if (input[7] >= 1478.4205) {
        var522 = 0.010258014;
    } else {
        var522 = -0.0054698586;
    }
    double var523;
    if (input[1] >= 26.2199) {
        var523 = 0.0031204645;
    } else {
        var523 = -0.0064520235;
    }
    double var524;
    if (input[0] >= -52.205) {
        var524 = 0.0071599944;
    } else {
        var524 = -0.004053106;
    }
    double var525;
    if (input[0] >= -52.205) {
        var525 = 0.0078063863;
    } else {
        var525 = -0.0040980447;
    }
    double var526;
    if (input[5] >= 0.1189255) {
        var526 = 0.00900359;
    } else {
        var526 = -0.0058162655;
    }
    double var527;
    if (input[1] >= 20.38035) {
        var527 = 0.0082687205;
    } else {
        var527 = -0.0068820575;
    }
    double var528;
    if (input[0] >= -52.78) {
        var528 = 0.010537253;
    } else {
        var528 = -0.00937936;
    }
    double var529;
    if (input[3] >= -45.0) {
        var529 = 0.0132207;
    } else {
        var529 = -0.00084175385;
    }
    double var530;
    if (input[7] >= 1450.8723) {
        var530 = 0.009431798;
    } else {
        var530 = -0.0055355076;
    }
    double var531;
    if (input[1] >= 26.39775) {
        var531 = 0.003825672;
    } else {
        var531 = -0.010431528;
    }
    double var532;
    if (input[1] >= 20.2995) {
        var532 = 0.004629269;
    } else {
        var532 = -0.006577437;
    }
    double var533;
    if (input[0] >= -53.559998) {
        var533 = 0.006828179;
    } else {
        var533 = -0.0047756094;
    }
    double var534;
    if (input[10] >= 8.14498) {
        var534 = 0.0076005543;
    } else {
        var534 = -0.007010631;
    }
    double var535;
    if (input[0] >= -53.504997) {
        var535 = 0.0064308494;
    } else {
        var535 = -0.0045810523;
    }
    double var536;
    if (input[1] >= 20.38035) {
        var536 = 0.0044579483;
    } else {
        var536 = -0.0065813228;
    }
    double var537;
    if (input[10] >= 8.141666) {
        var537 = -0.0032895368;
    } else {
        var537 = 0.0078720655;
    }
    double var538;
    if (input[1] >= 20.38035) {
        var538 = 0.0052837674;
    } else {
        var538 = -0.005618752;
    }
    double var539;
    if (input[0] >= -52.61) {
        var539 = 0.01043359;
    } else {
        var539 = -0.0015491061;
    }
    double var540;
    if (input[1] >= 20.38035) {
        var540 = 0.007961311;
    } else {
        var540 = -0.0057062986;
    }
    double var541;
    if (input[4] >= 18.5) {
        if (input[4] >= 22.5) {
            var541 = -0.00420046;
        } else {
            var541 = 0.011384434;
        }
    } else {
        var541 = -0.0059513687;
    }
    double var542;
    if (input[3] >= -45.0) {
        var542 = 0.0041014175;
    } else {
        var542 = -0.0047081006;
    }
    double var543;
    if (input[1] >= 20.38035) {
        var543 = 0.0043294705;
    } else {
        var543 = -0.011634219;
    }
    double var544;
    if (input[0] >= -53.504997) {
        var544 = 0.005711251;
    } else {
        var544 = -0.008516243;
    }
    double var545;
    if (input[0] >= -52.215) {
        var545 = 0.006434434;
    } else {
        var545 = -0.0047095027;
    }
    double var546;
    if (input[0] >= -53.504997) {
        var546 = 0.005134707;
    } else {
        var546 = -0.0054808254;
    }
    double var547;
    if (input[1] >= 20.38035) {
        var547 = 0.0037390708;
    } else {
        var547 = -0.0064408155;
    }
    double var548;
    if (input[0] >= -53.559998) {
        var548 = 0.006268752;
    } else {
        var548 = -0.008819986;
    }
    double var549;
    if (input[0] >= -52.17) {
        var549 = 0.006616915;
    } else {
        var549 = -0.00446342;
    }
    double var550;
    if (input[5] >= 0.18366) {
        var550 = -0.011392258;
    } else {
        var550 = 0.0035402328;
    }
    double var551;
    if (input[4] >= 22.5) {
        var551 = -0.0044913366;
    } else {
        var551 = 0.008716213;
    }
    double var552;
    if (input[5] >= 0.1489205) {
        var552 = 0.007288267;
    } else {
        var552 = -0.005413586;
    }
    double var553;
    if (input[1] >= 19.87815) {
        var553 = 0.008181396;
    } else {
        var553 = -0.011203166;
    }
    double var554;
    if (input[0] >= -52.205) {
        var554 = 0.007055677;
    } else {
        var554 = -0.0037731384;
    }
    double var555;
    if (input[6] >= 114.64646) {
        var555 = 0.008953179;
    } else {
        var555 = -0.0032124661;
    }
    double var556;
    if (input[1] >= 16.1847) {
        var556 = 0.0069388337;
    } else {
        var556 = -0.0062241545;
    }
    double var557;
    if (input[1] >= 20.38035) {
        var557 = 0.007858347;
    } else {
        var557 = -0.0044340766;
    }
    double var558;
    if (input[0] >= -52.205) {
        var558 = 0.0063574933;
    } else {
        var558 = -0.0039001212;
    }
    double var559;
    if (input[0] >= -53.504997) {
        var559 = 0.0056695305;
    } else {
        var559 = -0.004925826;
    }
    double var560;
    if (input[0] >= -52.205) {
        var560 = 0.00659879;
    } else {
        var560 = -0.0037454572;
    }
    double var561;
    if (input[1] >= 26.39775) {
        var561 = 0.003887469;
    } else {
        var561 = -0.0053660236;
    }
    double var562;
    if (input[1] >= 20.38035) {
        var562 = 0.006859962;
    } else {
        var562 = -0.004295273;
    }
    double var563;
    if (input[0] >= -53.85) {
        var563 = -0.011291306;
    } else {
        var563 = 0.0017599326;
    }
    double var564;
    if (input[5] >= 0.12662101) {
        var564 = 0.0086406795;
    } else {
        var564 = -0.0040381867;
    }
    double var565;
    if (input[4] >= 22.5) {
        var565 = -0.0045148665;
    } else {
        var565 = 0.008855169;
    }
    double var566;
    if (input[5] >= 0.12662101) {
        var566 = 0.008622984;
    } else {
        var566 = -0.0033145682;
    }
    double var567;
    if (input[0] >= -52.205) {
        var567 = 0.006008547;
    } else {
        var567 = -0.0042477357;
    }
    double var568;
    if (input[10] >= 8.141666) {
        var568 = -0.0059007737;
    } else {
        var568 = 0.0031411133;
    }
    double var569;
    if (input[7] >= 1553.9231) {
        var569 = 0.007871033;
    } else {
        var569 = -0.0039084167;
    }
    double var570;
    if (input[0] >= -53.504997) {
        var570 = 0.005733024;
    } else {
        var570 = -0.004068123;
    }
    double var571;
    if (input[1] >= 20.507149) {
        var571 = 0.0027941286;
    } else {
        var571 = -0.009994582;
    }
    double var572;
    if (input[0] >= -52.205) {
        var572 = 0.006386131;
    } else {
        var572 = -0.00428986;
    }
    double var573;
    if (input[1] >= 20.38035) {
        var573 = 0.0039034633;
    } else {
        var573 = -0.0058124606;
    }
    double var574;
    if (input[0] >= -52.205) {
        var574 = 0.005783351;
    } else {
        var574 = -0.004632237;
    }
    double var575;
    if (input[7] >= 2576.2676) {
        var575 = -0.0032908071;
    } else {
        var575 = 0.0085554905;
    }
    double var576;
    if (input[10] >= 8.14498) {
        var576 = 0.0039158664;
    } else {
        var576 = -0.013498008;
    }
    double var577;
    if (input[4] >= 18.5) {
        var577 = 0.003771516;
    } else {
        var577 = -0.0047882884;
    }
    double var578;
    if (input[0] >= -52.205) {
        var578 = 0.0049906853;
    } else {
        var578 = -0.0037427896;
    }
    double var579;
    if (input[0] >= -53.559998) {
        var579 = 0.0054890956;
    } else {
        var579 = -0.0041257176;
    }
    double var580;
    if (input[1] >= 20.336552) {
        var580 = 0.007337283;
    } else {
        var580 = -0.003670615;
    }
    double var581;
    if (input[10] >= 8.14498) {
        var581 = 0.0029232444;
    } else {
        var581 = -0.008577603;
    }
    double var582;
    if (input[0] >= -52.205) {
        var582 = 0.0060631232;
    } else {
        var582 = -0.0040247585;
    }
    double var583;
    if (input[1] >= 20.507149) {
        var583 = 0.0032927159;
    } else {
        var583 = -0.008431418;
    }
    double var584;
    if (input[0] >= -52.085) {
        var584 = 0.0070805624;
    } else {
        var584 = -0.003894555;
    }
    double var585;
    if (input[0] >= -51.745003) {
        var585 = 0.0065523176;
    } else {
        var585 = -0.004496656;
    }
    double var586;
    if (input[7] >= 1547.8013) {
        var586 = 0.011597716;
    } else {
        var586 = -0.003870281;
    }
    double var587;
    if (input[1] >= 16.1847) {
        var587 = 0.0037013653;
    } else {
        var587 = -0.0034869977;
    }
    double var588;
    if (input[10] >= 8.141666) {
        var588 = -0.0052279183;
    } else {
        var588 = 0.0028925927;
    }
    double var589;
    if (input[0] >= -52.205) {
        var589 = 0.005959339;
    } else {
        var589 = -0.0069755213;
    }
    double var590;
    if (input[10] >= 8.141666) {
        var590 = -0.006183199;
    } else {
        var590 = 0.0026029327;
    }
    double var591;
    if (input[7] >= 1529.4358) {
        var591 = 0.007471842;
    } else {
        var591 = -0.0040642926;
    }
    double var592;
    if (input[1] >= 25.853) {
        var592 = 0.0027661612;
    } else {
        var592 = -0.004135025;
    }
    double var593;
    if (input[0] >= -52.205) {
        var593 = 0.0065519563;
    } else {
        var593 = -0.003773141;
    }
    double var594;
    if (input[0] >= -52.205) {
        var594 = 0.005957657;
    } else {
        var594 = -0.007591326;
    }
    double var595;
    if (input[0] >= -51.745003) {
        var595 = 0.0061333436;
    } else {
        var595 = -0.0026507748;
    }
    double var596;
    if (input[1] >= 20.38035) {
        var596 = 0.0042570415;
    } else {
        var596 = -0.004651287;
    }
    double var597;
    if (input[1] >= 20.507149) {
        var597 = 0.0036387101;
    } else {
        var597 = -0.0040999036;
    }
    double var598;
    if (input[1] >= 20.2995) {
        var598 = 0.0032586828;
    } else {
        var598 = -0.0041296296;
    }
    double var599;
    if (input[5] >= 0.18366) {
        var599 = -0.006050516;
    } else {
        var599 = 0.0026183547;
    }
    double var600;
    if (input[0] >= -53.504997) {
        var600 = 0.008889021;
    } else {
        var600 = -0.0041361884;
    }
    double var601;
    if (input[0] >= -53.504997) {
        var601 = 0.008084416;
    } else {
        var601 = -0.0031886622;
    }
    double var602;
    if (input[0] >= -53.504997) {
        var602 = 0.005987908;
    } else {
        var602 = -0.0031459152;
    }
    double var603;
    if (input[0] >= -51.745003) {
        var603 = 0.0060974853;
    } else {
        var603 = -0.004148623;
    }
    double var604;
    if (input[7] >= 2576.2676) {
        var604 = -0.004230076;
    } else {
        var604 = 0.009181659;
    }
    double var605;
    if (input[0] >= -53.504997) {
        var605 = 0.004868874;
    } else {
        var605 = -0.00448055;
    }
    double var606;
    if (input[10] >= 8.141666) {
        var606 = -0.0051349937;
    } else {
        var606 = 0.0023626874;
    }
    double var607;
    if (input[0] >= -52.385) {
        var607 = 0.009065602;
    } else {
        var607 = -0.0033882314;
    }
    double var608;
    if (input[0] >= -51.83) {
        var608 = 0.005512461;
    } else {
        var608 = -0.0031217632;
    }
    double var609;
    if (input[1] >= 25.949348) {
        var609 = 0.0021821551;
    } else {
        var609 = -0.004550742;
    }
    double var610;
    if (input[0] >= -53.504997) {
        var610 = 0.008039105;
    } else {
        var610 = -0.0067723924;
    }
    double var611;
    if (input[0] >= -52.205) {
        var611 = 0.0039226688;
    } else {
        var611 = -0.0035159034;
    }
    double var612;
    if (input[7] >= 1718.192) {
        var612 = 0.0073038167;
    } else {
        var612 = -0.0015062083;
    }
    double var613;
    if (input[10] >= 8.141666) {
        var613 = -0.005960965;
    } else {
        var613 = 0.0053938814;
    }
    double var614;
    if (input[10] >= 8.210182) {
        var614 = 0.0070724795;
    } else {
        var614 = -0.001125912;
    }
    double var615;
    if (input[1] >= 20.38035) {
        var615 = 0.003592632;
    } else {
        var615 = -0.004680981;
    }
    double var616;
    if (input[1] >= 20.336552) {
        var616 = 0.006201632;
    } else {
        var616 = -0.005308553;
    }
    double var617;
    if (input[5] >= 0.18366) {
        var617 = -0.010703577;
    } else {
        var617 = 0.006121974;
    }
    double var618;
    if (input[1] >= 24.701199) {
        var618 = 0.0012376563;
    } else {
        var618 = -0.009972871;
    }
    double var619;
    if (input[0] >= -52.04) {
        var619 = 0.005815933;
    } else {
        var619 = -0.0035803702;
    }
    double var620;
    if (input[0] >= -52.205) {
        var620 = 0.005513991;
    } else {
        var620 = -0.0028736803;
    }
    double var621;
    if (input[0] >= -52.205) {
        var621 = 0.005707711;
    } else {
        var621 = -0.0038594268;
    }
    double var622;
    if (input[0] >= -53.355) {
        var622 = 0.0001240258;
    } else {
        var622 = 0.0061038346;
    }
    double var623;
    if (input[10] >= 8.14498) {
        var623 = 0.0029942382;
    } else {
        var623 = -0.0044059576;
    }
    double var624;
    if (input[10] >= 8.636348) {
        var624 = -0.0025869638;
    } else {
        var624 = 0.006216002;
    }
    double var625;
    if (input[0] >= -51.745003) {
        var625 = 0.0056489534;
    } else {
        var625 = -0.0031440079;
    }
    double var626;
    if (input[1] >= 20.38035) {
        var626 = 0.0070099207;
    } else {
        var626 = -0.0027558869;
    }
    double var627;
    if (input[4] >= 22.5) {
        var627 = -0.00499131;
    } else {
        var627 = 0.003633386;
    }
    double var628;
    if (input[0] >= -53.85) {
        var628 = -0.0037942086;
    } else {
        var628 = 0.005322755;
    }
    double var629;
    if (input[4] >= 22.5) {
        var629 = -0.004588698;
    } else {
        var629 = 0.0035780568;
    }
    double var630;
    if (input[0] >= -52.78) {
        var630 = 0.007706482;
    } else {
        var630 = -0.0029820453;
    }
    double var631;
    if (input[10] >= 8.14498) {
        var631 = 0.0034490016;
    } else {
        var631 = -0.0031637903;
    }
    double var632;
    if (input[1] >= 20.38035) {
        var632 = 0.00316986;
    } else {
        var632 = -0.004681731;
    }
    double var633;
    if (input[4] >= 22.5) {
        var633 = -0.004460336;
    } else {
        var633 = 0.00850859;
    }
    double var634;
    if (input[1] >= 20.38035) {
        var634 = 0.005893222;
    } else {
        var634 = -0.004037445;
    }
    double var635;
    if (input[10] >= 8.14498) {
        var635 = 0.002571961;
    } else {
        var635 = -0.0036333285;
    }
    double var636;
    if (input[10] >= 8.14498) {
        var636 = 0.0022880556;
    } else {
        var636 = -0.010245745;
    }
    double var637;
    if (input[0] >= -52.205) {
        var637 = 0.0053082495;
    } else {
        var637 = -0.006875156;
    }
    double var638;
    if (input[10] >= 8.1720295) {
        var638 = 0.003092787;
    } else {
        var638 = -0.0045425645;
    }
    double var639;
    if (input[0] >= -53.504997) {
        var639 = 0.0069779158;
    } else {
        var639 = -0.0034365826;
    }
    double var640;
    if (input[4] >= 22.5) {
        var640 = -0.004981045;
    } else {
        var640 = 0.0026776337;
    }
    double var641;
    if (input[0] >= -51.745003) {
        var641 = 0.004914682;
    } else {
        var641 = -0.0032469213;
    }
    double var642;
    if (input[0] >= -51.745003) {
        var642 = 0.0047568353;
    } else {
        var642 = -0.0026319677;
    }
    double var643;
    if (input[0] >= -53.504997) {
        var643 = 0.004184797;
    } else {
        var643 = -0.007984239;
    }
    double var644;
    if (input[7] >= 2576.2676) {
        var644 = -0.0042416835;
    } else {
        var644 = 0.0049344683;
    }
    double var645;
    if (input[1] >= 25.949348) {
        var645 = 0.0022386229;
    } else {
        var645 = -0.0051939925;
    }
    double var646;
    if (input[0] >= -52.17) {
        var646 = 0.0049118605;
    } else {
        var646 = -0.0024519616;
    }
    double var647;
    if (input[0] >= -51.77) {
        var647 = 0.004574743;
    } else {
        var647 = -0.0032892327;
    }
    double var648;
    if (input[0] >= -52.205) {
        var648 = 0.0047010873;
    } else {
        var648 = -0.006508227;
    }
    double var649;
    if (input[7] >= 1547.8013) {
        var649 = 0.010600467;
    } else {
        var649 = -0.0036628663;
    }
    double var650;
    if (input[0] >= -52.205) {
        var650 = 0.0041247476;
    } else {
        var650 = -0.0033029784;
    }
    double var651;
    if (input[0] >= -52.215) {
        var651 = 0.004644645;
    } else {
        var651 = -0.0028752065;
    }
    double var652;
    if (input[10] >= 8.276438) {
        var652 = 0.0021509407;
    } else {
        var652 = -0.013032287;
    }
    double var653;
    if (input[1] >= 20.336552) {
        var653 = 0.0036299012;
    } else {
        var653 = -0.004318205;
    }
    double var654;
    if (input[0] >= -53.85) {
        var654 = -0.004882695;
    } else {
        var654 = 0.0016610764;
    }
    double var655;
    if (input[5] >= 0.18366) {
        var655 = -0.008880524;
    } else {
        var655 = 0.0021506902;
    }
    double var656;
    if (input[10] >= 7.9108906) {
        if (input[10] >= 8.150295) {
            var656 = -0.03298153;
        } else {
            var656 = -0.007692308;
        }
    } else {
        if (input[7] >= 3480.2573) {
            var656 = 0.096059114;
        } else {
            var656 = 0.03846154;
        }
    }
    double var657;
    if (input[5] >= 0.209375) {
        var657 = 0.0861135;
    } else {
        if (input[5] >= 0.18366) {
            var657 = -0.0103568295;
        } else {
            var657 = -0.03261039;
        }
    }
    double var658;
    if (input[5] >= 0.209375) {
        var658 = 0.079661466;
    } else {
        if (input[10] >= 8.14498) {
            var658 = -0.032258827;
        } else {
            var658 = -0.007318993;
        }
    }
    double var659;
    if (input[5] >= 0.209375) {
        var659 = 0.073518775;
    } else {
        if (input[10] >= 8.14498) {
            var659 = -0.031894997;
        } else {
            var659 = -0.009709835;
        }
    }
    double var660;
    if (input[6] >= 128.78787) {
        var660 = 0.070057906;
    } else {
        if (input[10] >= 8.14498) {
            var660 = -0.031569827;
        } else {
            var660 = -0.0102658365;
        }
    }
    double var661;
    if (input[5] >= 0.209375) {
        var661 = 0.0646522;
    } else {
        if (input[10] >= 8.14498) {
            var661 = -0.031262558;
        } else {
            var661 = -0.006424598;
        }
    }
    double var662;
    if (input[5] >= 0.209375) {
        var662 = 0.060819056;
    } else {
        if (input[10] >= 8.150627) {
            var662 = -0.03094986;
        } else {
            var662 = -0.0060350155;
        }
    }
    double var663;
    if (input[5] >= 0.212403) {
        var663 = 0.05884943;
    } else {
        var663 = -0.030680412;
    }
    double var664;
    if (input[5] >= 0.209375) {
        var664 = 0.05448121;
    } else {
        var664 = -0.03038392;
    }
    double var665;
    if (input[5] >= 0.209375) {
        var665 = 0.05217446;
    } else {
        if (input[5] >= 0.18366) {
            var665 = -0.007588386;
        } else {
            var665 = -0.030076701;
        }
    }
    double var666;
    if (input[5] >= 0.209375) {
        var666 = 0.049951658;
    } else {
        if (input[5] >= 0.18366) {
            var666 = -0.004577622;
        } else {
            var666 = -0.029842181;
        }
    }
    double var667;
    if (input[5] >= 0.209375) {
        var667 = 0.047902163;
    } else {
        if (input[10] >= 8.150627) {
            var667 = -0.029576937;
        } else {
            var667 = -0.006761826;
        }
    }
    double var668;
    if (input[6] >= 126.76767) {
        var668 = 0.046192646;
    } else {
        if (input[10] >= 8.14498) {
            var668 = -0.029338866;
        } else {
            var668 = -0.0065929294;
        }
    }
    double var669;
    if (input[5] >= 0.209375) {
        var669 = 0.044583067;
    } else {
        if (input[10] >= 8.177676) {
            var669 = -0.029087493;
        } else {
            var669 = -0.0056667873;
        }
    }
    double var670;
    if (input[5] >= 0.209375) {
        if (input[0] >= -56.805) {
            var670 = 0.044231776;
        } else {
            var670 = 0.019985707;
        }
    } else {
        if (input[10] >= 8.203112) {
            var670 = -0.028862586;
        } else {
            var670 = -0.0049246172;
        }
    }
    double var671;
    if (input[5] >= 0.209375) {
        if (input[0] >= -56.065002) {
            var671 = 0.04263423;
        } else {
            var671 = 0.01939991;
        }
    } else {
        if (input[10] >= 8.172361) {
            var671 = -0.02865458;
        } else {
            var671 = -0.0053938935;
        }
    }
    double var672;
    if (input[5] >= 0.209375) {
        var672 = 0.041518215;
    } else {
        if (input[5] >= 0.176941) {
            var672 = -0.009347733;
        } else {
            var672 = -0.028444652;
        }
    }
    double var673;
    if (input[6] >= 128.78787) {
        var673 = 0.040247723;
    } else {
        if (input[2] >= -60.0) {
            var673 = -0.0056001116;
        } else {
            var673 = -0.028422823;
        }
    }
    double var674;
    if (input[5] >= 0.209375) {
        if (input[0] >= -56.805) {
            var674 = 0.039197195;
        } else {
            var674 = 0.01701834;
        }
    } else {
        if (input[4] >= 16.5) {
            var674 = -0.028112417;
        } else {
            var674 = -0.00888557;
        }
    }
    double var675;
    if (input[5] >= 0.209375) {
        if (input[0] >= -56.805) {
            var675 = 0.038270235;
        } else {
            var675 = 0.016466169;
        }
    } else {
        if (input[10] >= 8.14498) {
            var675 = -0.02790322;
        } else {
            var675 = -0.004351429;
        }
    }
    double var676;
    if (input[5] >= 0.209375) {
        var676 = 0.036570355;
    } else {
        var676 = -0.027800728;
    }
    double var677;
    if (input[5] >= 0.209375) {
        if (input[0] >= -56.805) {
            var677 = 0.036575485;
        } else {
            var677 = 0.015115631;
        }
    } else {
        if (input[10] >= 8.184748) {
            var677 = -0.027546767;
        } else {
            var677 = -0.0048160073;
        }
    }
    double var678;
    if (input[6] >= 128.78787) {
        var678 = 0.035745032;
    } else {
        if (input[6] >= 122.72727) {
            var678 = 0.0009140271;
        } else {
            var678 = -0.027384877;
        }
    }
    double var679;
    if (input[5] >= 0.209375) {
        if (input[0] >= -56.805) {
            var679 = 0.035111867;
        } else {
            var679 = 0.013819316;
        }
    } else {
        var679 = -0.027312705;
    }
    double var680;
    if (input[5] >= 0.22475949) {
        var680 = 0.03428354;
    } else {
        if (input[5] >= 0.18366) {
            var680 = -0.0010241949;
        } else {
            var680 = -0.027097477;
        }
    }
    double var681;
    if (input[6] >= 122.72727) {
        if (input[6] >= 128.78787) {
            var681 = 0.033699814;
        } else {
            var681 = 0.003374317;
        }
    } else {
        var681 = -0.026941935;
    }
    double var682;
    if (input[5] >= 0.221778) {
        var682 = 0.033130538;
    } else {
        if (input[5] >= 0.18366) {
            var682 = -0.00088200934;
        } else {
            var682 = -0.026792392;
        }
    }
    double var683;
    if (input[5] >= 0.212403) {
        var683 = 0.032550775;
    } else {
        if (input[4] >= 16.5) {
            var683 = -0.026708586;
        } else {
            var683 = -0.0045965794;
        }
    }
    double var684;
    if (input[6] >= 128.78787) {
        var684 = 0.032050084;
    } else {
        if (input[6] >= 122.72727) {
            var684 = 0.0014335798;
        } else {
            var684 = -0.02653408;
        }
    }
    double var685;
    if (input[5] >= 0.221778) {
        var685 = 0.031470563;
    } else {
        if (input[7] >= 2576.2676) {
            var685 = -0.0043499656;
        } else {
            var685 = -0.026659492;
        }
    }
    double var686;
    if (input[6] >= 122.72727) {
        if (input[6] >= 129.29292) {
            var686 = 0.031183247;
        } else {
            var686 = 0.0023413734;
        }
    } else {
        var686 = -0.026310487;
    }
    double var687;
    if (input[10] >= 8.14498) {
        var687 = -0.026153913;
    } else {
        if (input[6] >= 128.78787) {
            var687 = 0.03072443;
        } else {
            var687 = 0.0019482126;
        }
    }
    double var688;
    if (input[6] >= 128.78787) {
        var688 = 0.030344775;
    } else {
        if (input[2] >= -60.0) {
            var688 = -0.0026720075;
        } else {
            var688 = -0.026379287;
        }
    }
    double var689;
    if (input[5] >= 0.18366) {
        if (input[0] >= -56.805) {
            var689 = 0.030508613;
        } else {
            var689 = 0.0054019126;
        }
    } else {
        var689 = -0.025912771;
    }
    double var690;
    if (input[10] >= 8.14498) {
        var690 = -0.025804346;
    } else {
        if (input[5] >= 0.221778) {
            var690 = 0.029616697;
        } else {
            var690 = 0.005231114;
        }
    }
    double var691;
    if (input[10] >= 8.14498) {
        var691 = -0.02570858;
    } else {
        if (input[5] >= 0.221778) {
            var691 = 0.029207526;
        } else {
            var691 = 0.002661474;
        }
    }
    double var692;
    if (input[5] >= 0.209375) {
        if (input[0] >= -55.190002) {
            var692 = 0.029242441;
        } else {
            var692 = 0.008746137;
        }
    } else {
        if (input[7] >= 2576.2676) {
            var692 = -0.003780376;
        } else {
            var692 = -0.02558795;
        }
    }
    double var693;
    if (input[5] >= 0.18366) {
        if (input[5] >= 0.221778) {
            var693 = 0.028571088;
        } else {
            var693 = 0.0033131745;
        }
    } else {
        var693 = -0.02545313;
    }
    double var694;
    if (input[5] >= 0.18366) {
        if (input[1] >= 28.85955) {
            var694 = 0.011934549;
        } else {
            var694 = 0.028831964;
        }
    } else {
        var694 = -0.025395826;
    }
    double var695;
    if (input[5] >= 0.209375) {
        if (input[1] >= 27.08775) {
            var695 = 0.010037193;
        } else {
            var695 = 0.028347949;
        }
    } else {
        var695 = -0.025406782;
    }
    double var696;
    if (input[6] >= 128.78787) {
        var696 = 0.027685339;
    } else {
        if (input[4] >= 17.5) {
            var696 = -0.025586957;
        } else {
            var696 = -0.0027306352;
        }
    }
    double var697;
    if (input[5] >= 0.22475949) {
        var697 = 0.027458305;
    } else {
        var697 = -0.025610698;
    }
    double var698;
    if (input[5] >= 0.18366) {
        if (input[5] >= 0.221778) {
            var698 = 0.027070794;
        } else {
            var698 = 0.0022495892;
        }
    } else {
        var698 = -0.025015434;
    }
    double var699;
    if (input[5] >= 0.18366) {
        if (input[5] >= 0.221778) {
            var699 = 0.026990924;
        } else {
            var699 = 0.003381392;
        }
    } else {
        var699 = -0.024870439;
    }
    double var700;
    if (input[5] >= 0.18366) {
        if (input[1] >= 27.08775) {
            var700 = 0.0023696965;
        } else {
            if (input[3] >= -43.0) {
                var700 = 0.010834381;
            } else {
                var700 = 0.028571725;
            }
        }
    } else {
        var700 = -0.024769811;
    }
    double var701;
    if (input[5] >= 0.18366) {
        if (input[1] >= 27.08775) {
            var701 = 0.0035239093;
        } else {
            var701 = 0.02735808;
        }
    } else {
        var701 = -0.024692237;
    }
    double var702;
    if (input[5] >= 0.18366) {
        if (input[1] >= 27.08775) {
            var702 = 0.0031780873;
        } else {
            var702 = 0.02631445;
        }
    } else {
        var702 = -0.024592245;
    }
    double var703;
    if (input[5] >= 0.18366) {
        if (input[5] >= 0.221778) {
            var703 = 0.026238127;
        } else {
            var703 = 0.0014533194;
        }
    } else {
        var703 = -0.024483098;
    }
    double var704;
    if (input[6] >= 122.72727) {
        if (input[1] >= 27.08775) {
            var704 = 0.0041348836;
        } else {
            var704 = 0.026888613;
        }
    } else {
        var704 = -0.024377167;
    }
    double var705;
    if (input[7] >= 2576.2676) {
        if (input[5] >= 0.233705) {
            var705 = 0.025725309;
        } else {
            var705 = 0.0060706604;
        }
    } else {
        var705 = -0.024836022;
    }
    double var706;
    if (input[7] >= 2576.2676) {
        if (input[10] >= 7.6479096) {
            var706 = 0.003737424;
        } else {
            var706 = 0.025620252;
        }
    } else {
        var706 = -0.024699217;
    }
    double var707;
    if (input[5] >= 0.18366) {
        var707 = 0.024312314;
    } else {
        var707 = -0.024077827;
    }
    double var708;
    if (input[5] >= 0.18366) {
        if (input[5] >= 0.221778) {
            var708 = 0.025262967;
        } else {
            var708 = 0.0034849562;
        }
    } else {
        var708 = -0.023991523;
    }
    double var709;
    if (input[5] >= 0.18366) {
        if (input[5] >= 0.22475949) {
            var709 = 0.024934841;
        } else {
            var709 = 0.0018502859;
        }
    } else {
        var709 = -0.023948433;
    }
    double var710;
    if (input[5] >= 0.18366) {
        if (input[1] >= 27.08775) {
            var710 = -0.00023213564;
        } else {
            var710 = 0.024558652;
        }
    } else {
        var710 = -0.02390213;
    }
    double var711;
    if (input[5] >= 0.18366) {
        if (input[5] >= 0.221778) {
            var711 = 0.024767911;
        } else {
            var711 = 0.0020180254;
        }
    } else {
        var711 = -0.0237581;
    }
    double var712;
    if (input[5] >= 0.18366) {
        if (input[1] >= 25.853) {
            var712 = 0.0012296368;
        } else {
            var712 = 0.02420967;
        }
    } else {
        var712 = -0.02366232;
    }
    double var713;
    if (input[5] >= 0.18366) {
        if (input[5] >= 0.221778) {
            var713 = 0.024446612;
        } else {
            var713 = 0.008080753;
        }
    } else {
        var713 = -0.023567839;
    }
    double var714;
    if (input[6] >= 128.78787) {
        var714 = 0.024116611;
    } else {
        var714 = -0.024228333;
    }
    double var715;
    if (input[10] >= 8.14498) {
        var715 = -0.023318974;
    } else {
        if (input[4] >= 21.5) {
            var715 = 0.0076326593;
        } else {
            var715 = 0.025793245;
        }
    }
    double var716;
    if (input[6] >= 122.72727) {
        if (input[6] >= 128.78787) {
            var716 = 0.023798944;
        } else {
            var716 = 0.003031045;
        }
    } else {
        var716 = -0.023202796;
    }
    double var717;
    if (input[5] >= 0.18366) {
        if (input[5] >= 0.221778) {
            var717 = 0.02350184;
        } else {
            var717 = 0.0015238625;
        }
    } else {
        var717 = -0.023129847;
    }
    double var718;
    if (input[5] >= 0.18366) {
        if (input[1] >= 26.14175) {
            var718 = 0.00021477244;
        } else {
            var718 = 0.022976676;
        }
    } else {
        var718 = -0.023044107;
    }
    double var719;
    if (input[5] >= 0.209375) {
        var719 = 0.024210058;
    } else {
        var719 = -0.023549434;
    }
    double var720;
    if (input[5] >= 0.18366) {
        var720 = 0.02201826;
    } else {
        var720 = -0.022853604;
    }
    double var721;
    if (input[5] >= 0.209375) {
        if (input[1] >= 22.71695) {
            var721 = 0.007776645;
        } else {
            var721 = 0.023011351;
        }
    } else {
        var721 = -0.023278425;
    }
    double var722;
    if (input[7] >= 2573.2068) {
        if (input[10] >= 7.5024714) {
            var722 = 0.008938202;
        } else {
            var722 = 0.022429693;
        }
    } else {
        var722 = -0.023435002;
    }
    double var723;
    if (input[10] >= 8.14498) {
        var723 = -0.02229168;
    } else {
        if (input[5] >= 0.221778) {
            var723 = 0.022709344;
        } else {
            var723 = 0.0015656243;
        }
    }
    double var724;
    if (input[5] >= 0.18366) {
        if (input[1] >= 25.51395) {
            var724 = 0.0006654696;
        } else {
            var724 = 0.023145614;
        }
    } else {
        var724 = -0.022328543;
    }
    double var725;
    if (input[5] >= 0.18366) {
        if (input[4] >= 19.5) {
            var725 = 0.010928495;
        } else {
            var725 = 0.023838935;
        }
    } else {
        var725 = -0.022224292;
    }
    double var726;
    if (input[6] >= 128.78787) {
        var726 = 0.02226272;
    } else {
        if (input[1] >= 17.67815) {
            var726 = -0.022905696;
        } else {
            var726 = -0.007768169;
        }
    }
    double var727;
    if (input[10] >= 8.14498) {
        var727 = -0.021960469;
    } else {
        if (input[6] >= 128.78787) {
            var727 = 0.022174679;
        } else {
            var727 = 0.0016399429;
        }
    }
    double var728;
    if (input[7] >= 2576.2676) {
        var728 = 0.020318491;
    } else {
        if (input[1] >= 20.113499) {
            var728 = -0.022085888;
        } else {
            var728 = -0.007589689;
        }
    }
    double var729;
    if (input[10] >= 7.9137745) {
        var729 = -0.022269571;
    } else {
        var729 = 0.022961106;
    }
    double var730;
    if (input[5] >= 0.18366) {
        if (input[5] >= 0.221778) {
            var730 = 0.02150022;
        } else {
            var730 = 0.0034271793;
        }
    } else {
        var730 = -0.021540815;
    }
    double var731;
    if (input[6] >= 122.72727) {
        if (input[1] >= 16.1847) {
            var731 = 0.010202422;
        } else {
            var731 = 0.023070164;
        }
    } else {
        var731 = -0.021585768;
    }
    double var732;
    if (input[7] >= 2576.2676) {
        if (input[4] >= 19.5) {
            var732 = 0.008987686;
        } else {
            var732 = 0.026060343;
        }
    } else {
        if (input[1] >= 20.47) {
            var732 = -0.021611903;
        } else {
            var732 = -0.007937992;
        }
    }
    double var733;
    if (input[5] >= 0.18366) {
        if (input[5] >= 0.221778) {
            var733 = 0.02116056;
        } else {
            var733 = 0.0011708877;
        }
    } else {
        var733 = -0.02116509;
    }
    double var734;
    if (input[10] >= 8.14498) {
        var734 = -0.02111532;
    } else {
        if (input[5] >= 0.221778) {
            var734 = 0.021156406;
        } else {
            var734 = 0.0033537627;
        }
    }
    double var735;
    if (input[7] >= 2573.2068) {
        if (input[7] >= 3895.5208) {
            var735 = 0.020169927;
        } else {
            var735 = 0.005611232;
        }
    } else {
        var735 = -0.022020275;
    }
    double var736;
    if (input[5] >= 0.18366) {
        if (input[5] >= 0.221778) {
            var736 = 0.020758888;
        } else {
            var736 = 0.0012110042;
        }
    } else {
        var736 = -0.020772018;
    }
    double var737;
    if (input[5] >= 0.18366) {
        if (input[4] >= 21.5) {
            var737 = 0.0028571133;
        } else {
            var737 = 0.022480933;
        }
    } else {
        var737 = -0.020561626;
    }
    double var738;
    if (input[5] >= 0.18366) {
        if (input[4] >= 19.5) {
            var738 = 0.008029548;
        } else {
            var738 = 0.021581344;
        }
    } else {
        var738 = -0.020336047;
    }
    double var739;
    if (input[5] >= 0.221778) {
        var739 = 0.020358946;
    } else {
        var739 = -0.019249814;
    }
    double var740;
    if (input[5] >= 0.209375) {
        var740 = 0.021626197;
    } else {
        var740 = -0.020820944;
    }
    double var741;
    if (input[7] >= 2576.2676) {
        if (input[7] >= 3915.9268) {
            var741 = 0.01897616;
        } else {
            var741 = 0.005955577;
        }
    } else {
        var741 = -0.017415334;
    }
    double var742;
    if (input[7] >= 2576.2676) {
        var742 = 0.018427698;
    } else {
        var742 = -0.016989226;
    }
    double var743;
    if (input[10] >= 8.14498) {
        var743 = -0.019691752;
    } else {
        if (input[4] >= 19.5) {
            var743 = 0.0034793508;
        } else {
            var743 = 0.020713104;
        }
    }
    double var744;
    if (input[7] >= 2576.2676) {
        var744 = 0.016531993;
    } else {
        var744 = -0.016725812;
    }
    double var745;
    if (input[7] >= 2573.2068) {
        var745 = 0.017964771;
    } else {
        var745 = -0.016715283;
    }
    double var746;
    if (input[5] >= 0.18366) {
        if (input[4] >= 19.5) {
            var746 = 0.0012686356;
        } else {
            var746 = 0.026314108;
        }
    } else {
        var746 = -0.019423617;
    }
    double var747;
    if (input[5] >= 0.18366) {
        var747 = 0.017290737;
    } else {
        var747 = -0.019045485;
    }
    double var748;
    if (input[5] >= 0.18366) {
        if (input[4] >= 19.5) {
            var748 = 0.0010196493;
        } else {
            var748 = 0.019937372;
        }
    } else {
        var748 = -0.019047419;
    }
    double var749;
    if (input[6] >= 128.78787) {
        var749 = 0.018898163;
    } else {
        var749 = -0.018238893;
    }
    double var750;
    if (input[5] >= 0.221778) {
        var750 = 0.018761717;
    } else {
        var750 = -0.022457343;
    }
    double var751;
    if (input[6] >= 128.78787) {
        var751 = 0.018774722;
    } else {
        var751 = -0.018356692;
    }
    double var752;
    if (input[7] >= 2576.2676) {
        var752 = 0.019549884;
    } else {
        var752 = -0.015070549;
    }
    double var753;
    if (input[5] >= 0.18366) {
        if (input[4] >= 19.5) {
            var753 = 0.0003954059;
        } else {
            var753 = 0.01959719;
        }
    } else {
        var753 = -0.018078467;
    }
    double var754;
    if (input[7] >= 2576.2676) {
        var754 = 0.015226508;
    } else {
        var754 = -0.020289294;
    }
    double var755;
    if (input[7] >= 2576.2676) {
        var755 = 0.017157389;
    } else {
        var755 = -0.014398557;
    }
    double var756;
    if (input[5] >= 0.18366) {
        if (input[4] >= 19.5) {
            var756 = -0.00050976133;
        } else {
            var756 = 0.019035256;
        }
    } else {
        var756 = -0.01796657;
    }
    double var757;
    if (input[7] >= 2426.283) {
        if (input[4] >= 19.5) {
            var757 = -0.0019767913;
        } else {
            var757 = 0.01845159;
        }
    } else {
        var757 = -0.017722059;
    }
    double var758;
    if (input[5] >= 0.209375) {
        var758 = 0.019494226;
    } else {
        var758 = -0.011370263;
    }
    double var759;
    if (input[5] >= 0.18366) {
        if (input[1] >= 16.1847) {
            var759 = 0.0004406712;
        } else {
            var759 = 0.0183231;
        }
    } else {
        var759 = -0.017447028;
    }
    double var760;
    if (input[7] >= 2576.2676) {
        var760 = 0.012610418;
    } else {
        var760 = -0.019668473;
    }
    double var761;
    if (input[5] >= 0.18366) {
        var761 = 0.014029338;
    } else {
        var761 = -0.01691699;
    }
    double var762;
    if (input[6] >= 128.78787) {
        var762 = 0.017546916;
    } else {
        if (input[1] >= 20.177551) {
            var762 = -0.019224495;
        } else {
            var762 = 0.0044251657;
        }
    }
    double var763;
    if (input[5] >= 0.18366) {
        if (input[1] >= 15.0877495) {
            var763 = 0.001569923;
        } else {
            var763 = 0.017018767;
        }
    } else {
        var763 = -0.016801674;
    }
    double var764;
    if (input[7] >= 2576.2676) {
        var764 = 0.01620995;
    } else {
        var764 = -0.013454928;
    }
    double var765;
    if (input[7] >= 2576.2676) {
        var765 = 0.013248252;
    } else {
        var765 = -0.018692868;
    }
    double var766;
    if (input[0] >= -53.825) {
        var766 = 0.010952103;
    } else {
        var766 = -0.014061344;
    }
    double var767;
    if (input[7] >= 2576.2676) {
        var767 = 0.016091147;
    } else {
        var767 = -0.0129376;
    }
    double var768;
    if (input[7] >= 2564.024) {
        var768 = 0.011938819;
    } else {
        var768 = -0.0123932995;
    }
    double var769;
    if (input[7] >= 2576.2676) {
        var769 = 0.012001341;
    } else {
        var769 = -0.018271334;
    }
    double var770;
    if (input[7] >= 2573.2068) {
        var770 = 0.018005263;
    } else {
        var770 = -0.01203931;
    }
    double var771;
    if (input[5] >= 0.209375) {
        var771 = 0.013246439;
    } else {
        var771 = -0.019808397;
    }
    double var772;
    if (input[5] >= 0.209375) {
        var772 = 0.01241722;
    } else {
        var772 = -0.010217039;
    }
    double var773;
    if (input[7] >= 2576.2676) {
        var773 = 0.012022792;
    } else {
        var773 = -0.011702727;
    }
    double var774;
    if (input[6] >= 126.76767) {
        var774 = 0.018753227;
    } else {
        var774 = -0.009246922;
    }
    double var775;
    if (input[7] >= 2576.2676) {
        var775 = 0.01091517;
    } else {
        var775 = -0.011043335;
    }
    double var776;
    if (input[9] >= 350.0) {
        var776 = 0.009725673;
    } else {
        var776 = -0.016078977;
    }
    double var777;
    if (input[6] >= 126.76767) {
        var777 = 0.018642116;
    } else {
        var777 = -0.010039736;
    }
    double var778;
    if (input[5] >= 0.209375) {
        var778 = 0.012392091;
    } else {
        var778 = -0.009761106;
    }
    double var779;
    if (input[7] >= 2576.2676) {
        var779 = 0.0111475885;
    } else {
        var779 = -0.010933365;
    }
    double var780;
    if (input[5] >= 0.209375) {
        var780 = 0.01219272;
    } else {
        var780 = -0.01017272;
    }
    double var781;
    if (input[1] >= 19.213902) {
        var781 = -0.006892148;
    } else {
        var781 = 0.0060661887;
    }
    double var782;
    if (input[0] >= -52.125) {
        var782 = 0.0038127594;
    } else {
        var782 = -0.0081519745;
    }
    double var783;
    if (input[5] >= 0.209375) {
        var783 = 0.012161384;
    } else {
        var783 = -0.009592168;
    }
    double var784;
    if (input[5] >= 0.209375) {
        var784 = 0.011873945;
    } else {
        var784 = -0.019216148;
    }
    double var785;
    if (input[1] >= 19.213902) {
        var785 = -0.010230648;
    } else {
        var785 = 0.011336967;
    }
    double var786;
    if (input[4] >= 19.5) {
        var786 = -0.006481711;
    } else {
        var786 = 0.0112236915;
    }
    double var787;
    if (input[6] >= 126.76767) {
        var787 = 0.011893276;
    } else {
        var787 = -0.009154432;
    }
    double var788;
    if (input[7] >= 2576.2676) {
        var788 = 0.017227305;
    } else {
        var788 = -0.010779925;
    }
    double var789;
    if (input[5] >= 0.209375) {
        var789 = 0.011760742;
    } else {
        var789 = -0.008582807;
    }
    double var790;
    if (input[5] >= 0.209375) {
        var790 = 0.011656123;
    } else {
        var790 = -0.008930723;
    }
    double var791;
    if (input[5] >= 0.209375) {
        var791 = 0.011393197;
    } else {
        var791 = -0.008899237;
    }
    double var792;
    if (input[1] >= 16.1847) {
        var792 = -0.008339669;
    } else {
        var792 = 0.011723006;
    }
    double var793;
    if (input[1] >= 19.213902) {
        var793 = -0.008185552;
    } else {
        var793 = 0.0065314504;
    }
    double var794;
    if (input[7] >= 2576.2676) {
        var794 = 0.01045228;
    } else {
        var794 = -0.01043249;
    }
    double var795;
    if (input[9] >= 350.0) {
        var795 = 0.017461227;
    } else {
        var795 = -0.008893556;
    }
    double var796;
    if (input[1] >= 15.40995) {
        var796 = -0.008906755;
    } else {
        var796 = 0.011310563;
    }
    double var797;
    if (input[4] >= 19.5) {
        var797 = -0.004707099;
    } else {
        var797 = 0.011213622;
    }
    double var798;
    if (input[4] >= 19.5) {
        var798 = -0.008838341;
    } else {
        var798 = 0.011506086;
    }
    double var799;
    if (input[6] >= 126.76767) {
        var799 = 0.011122167;
    } else {
        var799 = -0.008475083;
    }
    double var800;
    if (input[5] >= 0.209375) {
        var800 = 0.011382667;
    } else {
        var800 = -0.008538647;
    }
    double var801;
    if (input[1] >= 19.25815) {
        var801 = -0.008525116;
    } else {
        var801 = 0.010621674;
    }
    double var802;
    if (input[7] >= 2576.2676) {
        var802 = 0.01444862;
    } else {
        var802 = -0.010446121;
    }
    double var803;
    if (input[9] >= 350.0) {
        var803 = 0.015496119;
    } else {
        var803 = -0.009745851;
    }
    double var804;
    if (input[7] >= 2576.2676) {
        var804 = 0.009797954;
    } else {
        var804 = -0.010342931;
    }
    double var805;
    if (input[5] >= 0.209375) {
        var805 = 0.010856078;
    } else {
        var805 = -0.008753543;
    }
    double var806;
    if (input[5] >= 0.209375) {
        var806 = 0.010801735;
    } else {
        var806 = -0.00740525;
    }
    double var807;
    if (input[1] >= 19.213902) {
        var807 = -0.009122385;
    } else {
        var807 = 0.010240375;
    }
    double var808;
    if (input[5] >= 0.209375) {
        var808 = 0.010798157;
    } else {
        var808 = -0.008306867;
    }
    double var809;
    if (input[4] >= 19.5) {
        var809 = -0.0084722545;
    } else {
        var809 = 0.010968525;
    }
    double var810;
    if (input[4] >= 19.5) {
        var810 = -0.008518146;
    } else {
        var810 = 0.009619803;
    }
    double var811;
    if (input[1] >= 16.1847) {
        var811 = -0.009540787;
    } else {
        var811 = 0.0102267405;
    }
    double var812;
    if (input[4] >= 18.5) {
        var812 = -0.0034621742;
    } else {
        var812 = 0.009488302;
    }
    double var813;
    if (input[9] >= 350.0) {
        var813 = 0.010308904;
    } else {
        var813 = -0.008694984;
    }
    double var814;
    if (input[9] >= 350.0) {
        var814 = 0.015097454;
    } else {
        var814 = -0.008422292;
    }
    double var815;
    if (input[5] >= 0.209375) {
        var815 = 0.010785471;
    } else {
        var815 = -0.008542019;
    }
    double var816;
    if (input[1] >= 16.1847) {
        var816 = -0.0074638226;
    } else {
        var816 = 0.009618281;
    }
    double var817;
    if (input[10] >= 7.9108906) {
        var817 = -0.0068035624;
    } else {
        var817 = 0.009986115;
    }
    double var818;
    if (input[10] >= 7.9108906) {
        var818 = -0.007924839;
    } else {
        var818 = 0.009977807;
    }
    double var819;
    if (input[9] >= 350.0) {
        var819 = 0.009557771;
    } else {
        var819 = -0.008324006;
    }
    double var820;
    if (input[5] >= 0.209375) {
        var820 = 0.010901402;
    } else {
        var820 = -0.007040334;
    }
    double var821;
    if (input[1] >= 18.51495) {
        var821 = -0.008151459;
    } else {
        var821 = 0.00961709;
    }
    double var822;
    if (input[1] >= 19.213902) {
        var822 = -0.008065371;
    } else {
        var822 = 0.014174958;
    }
    double var823;
    if (input[10] >= 7.9108906) {
        var823 = -0.0067668976;
    } else {
        var823 = 0.010156682;
    }
    double var824;
    if (input[6] >= 126.76767) {
        var824 = 0.011226981;
    } else {
        var824 = -0.0077137793;
    }
    double var825;
    if (input[1] >= 18.82575) {
        var825 = -0.007197159;
    } else {
        var825 = 0.004945718;
    }
    double var826;
    if (input[4] >= 20.5) {
        var826 = -0.006771011;
    } else {
        var826 = 0.0045507993;
    }
    double var827;
    if (input[5] >= 0.209375) {
        var827 = 0.010637872;
    } else {
        var827 = -0.007781601;
    }
    double var828;
    if (input[10] >= 7.9108906) {
        var828 = -0.00663937;
    } else {
        var828 = 0.010092719;
    }
    double var829;
    if (input[4] >= 19.5) {
        var829 = -0.0068730377;
    } else {
        var829 = 0.008787503;
    }
    double var830;
    if (input[1] >= 16.854149) {
        var830 = -0.005064729;
    } else {
        var830 = 0.008402273;
    }
    double var831;
    if (input[9] >= 350.0) {
        var831 = 0.00811136;
    } else {
        var831 = -0.008326321;
    }
    double var832;
    if (input[9] >= 350.0) {
        var832 = 0.0076023987;
    } else {
        var832 = -0.008501968;
    }
    double var833;
    if (input[4] >= 19.5) {
        var833 = -0.0068805898;
    } else {
        var833 = 0.008938319;
    }
    double var834;
    if (input[10] >= 7.9108906) {
        var834 = -0.007466712;
    } else {
        var834 = 0.009937543;
    }
    double var835;
    if (input[4] >= 19.5) {
        var835 = -0.0064909244;
    } else {
        var835 = 0.008276287;
    }
    double var836;
    if (input[1] >= 16.1847) {
        var836 = -0.006837794;
    } else {
        var836 = 0.00831367;
    }
    double var837;
    if (input[10] >= 7.9108906) {
        var837 = -0.0075854296;
    } else {
        var837 = 0.01009585;
    }
    double var838;
    if (input[1] >= 16.1847) {
        var838 = -0.00588054;
    } else {
        var838 = 0.008491327;
    }
    double var839;
    if (input[4] >= 19.5) {
        var839 = -0.005609786;
    } else {
        var839 = 0.007881378;
    }
    double var840;
    if (input[4] >= 19.5) {
        var840 = -0.0069280327;
    } else {
        var840 = 0.0071834326;
    }
    double var841;
    if (input[4] >= 19.5) {
        var841 = -0.005144119;
    } else {
        var841 = 0.0070162425;
    }
    double var842;
    if (input[1] >= 16.1847) {
        var842 = -0.0054042353;
    } else {
        var842 = 0.007325244;
    }
    double var843;
    if (input[4] >= 19.5) {
        var843 = -0.0056062913;
    } else {
        var843 = 0.0069386857;
    }
    double var844;
    if (input[1] >= 16.1847) {
        var844 = -0.0059012542;
    } else {
        var844 = 0.0073268525;
    }
    double var845;
    if (input[1] >= 16.1847) {
        var845 = -0.0054277363;
    } else {
        var845 = 0.0069273706;
    }
    double var846;
    if (input[4] >= 19.5) {
        var846 = -0.0055074664;
    } else {
        var846 = 0.006574854;
    }
    double var847;
    if (input[4] >= 19.5) {
        var847 = -0.007061798;
    } else {
        var847 = 0.0064287423;
    }
    double var848;
    if (input[10] >= 7.9108906) {
        var848 = -0.0071929665;
    } else {
        var848 = 0.010153289;
    }
    double var849;
    if (input[4] >= 19.5) {
        var849 = -0.005612614;
    } else {
        var849 = 0.0066441395;
    }
    double var850;
    if (input[4] >= 19.5) {
        var850 = -0.0058942856;
    } else {
        var850 = 0.0062232357;
    }
    double var851;
    if (input[4] >= 19.5) {
        var851 = -0.006253883;
    } else {
        var851 = 0.006251813;
    }
    double var852;
    if (input[10] >= 7.9108906) {
        var852 = -0.0076844217;
    } else {
        var852 = 0.010140716;
    }
    double var853;
    if (input[2] >= -65.0) {
        var853 = 0.0056553516;
    } else {
        var853 = -0.0051644887;
    }
    double var854;
    if (input[1] >= 16.1847) {
        var854 = -0.006068013;
    } else {
        var854 = 0.0062001343;
    }
    double var855;
    if (input[1] >= 18.515549) {
        var855 = -0.004950022;
    } else {
        var855 = 0.006098825;
    }
    double var856;
    if (input[0] >= -52.665) {
        var856 = 0.003093449;
    } else {
        var856 = -0.0021927066;
    }
    double var857;
    if (input[1] >= 17.65335) {
        var857 = -0.004862066;
    } else {
        var857 = 0.006256272;
    }
    double var858;
    if (input[2] >= -64.0) {
        var858 = 0.004976859;
    } else {
        var858 = -0.0045563513;
    }
    double var859;
    if (input[1] >= 16.854149) {
        var859 = -0.0042109117;
    } else {
        var859 = 0.004506436;
    }
    double var860;
    if (input[2] >= -65.0) {
        var860 = 0.0056651686;
    } else {
        var860 = -0.00474218;
    }
    double var861;
    if (input[10] >= 7.9108906) {
        var861 = -0.008775732;
    } else {
        var861 = 0.010166345;
    }
    double var862;
    if (input[0] >= -52.96) {
        var862 = 0.0020577488;
    } else {
        var862 = -0.0027326364;
    }
    double var863;
    if (input[1] >= 17.007198) {
        var863 = -0.003949815;
    } else {
        var863 = 0.0047730296;
    }
    double var864;
    if (input[2] >= -64.0) {
        var864 = 0.004634557;
    } else {
        var864 = -0.0047007906;
    }
    double var865;
    if (input[10] >= 7.9108906) {
        var865 = -0.008594689;
    } else {
        var865 = 0.01021995;
    }
    double var866;
    if (input[2] >= -64.0) {
        var866 = 0.004829721;
    } else {
        var866 = -0.0051152655;
    }
    double var867;
    if (input[1] >= 16.854149) {
        var867 = -0.0040289517;
    } else {
        var867 = 0.004550726;
    }
    double var868;
    if (input[1] >= 16.854149) {
        var868 = -0.003459314;
    } else {
        var868 = 0.0043591824;
    }
    double var869;
    if (input[0] >= -52.815002) {
        var869 = 0.0028004702;
    } else {
        var869 = -0.0022688047;
    }
    double var870;
    if (input[2] >= -64.0) {
        var870 = 0.005410004;
    } else {
        var870 = -0.004671694;
    }
    double var871;
    if (input[4] >= 19.5) {
        var871 = -0.004476198;
    } else {
        var871 = 0.0051639457;
    }
    double softmaxInput[4] = {0.5 + (var1 + var2 + var3 + var4 + var5 + var6 + var7 + var8 + var9 + var10 + var11 + var12 + var13 + var14 + var15 + var16 + var17 + var18 + var19 + var20 + var21 + var22 + var23 + var24 + var25 + var26 + var27 + var28 + var29 + var30 + var31 + var32 + var33 + var34 + var35 + var36 + var37 + var38 + var39 + var40 + var41 + var42 + var43 + var44 + var45 + var46 + var47 + var48 + var49 + var50 + var51 + var52 + var53 + var54 + var55 + var56 + var57 + var58 + var59 + var60 + var61 + var62 + var63 + var64 + var65 + var66 + var67 + var68 + var69 + var70 + var71 + var72 + var73 + var74 + var75 + var76 + var77 + var78 + var79 + var80 + var81 + var82 + var83 + var84 + var85 + var86 + var87 + var88 + var89 + var90 + var91 + var92 + var93 + var94 + var95 + var96 + var97 + var98 + var99 + var100 + var101 + var102 + var103 + var104 + var105 + var106 + var107 + var108 + var109 + var110 + var111 + var112 + var113 + var114 + var115 + var116 + var117 + var118 + var119 + 0.0009420679 + var120 + var121 + var122 + var123 + var124 + 0.0010095014 + 0.0011940649 + 0.0014894282 + 0.0018039927 + -0.000015575992 + 0.0018162593 + var125 + 0.0013043593 + 0.00054785993 + 0.0005131519 + -0.0021172343 + 0.00061429496 + 0.00075149396 + 0.0017798515 + -0.0010765375 + -0.0015460466 + 0.0015407599 + 0.0012632005 + 0.001217169 + 0.0018528587 + 0.0008351874 + 0.001428299 + 0.00082196615 + 0.00029395695 + -0.00011607383 + 0.0018064514 + 0.0017337165 + 0.001113521 + 0.0011320778 + 0.00025263554 + -0.0013721836 + -0.00016982525 + 0.0022380354 + 0.0005838336 + -0.0022974522 + 0.0018673906 + 0.00084391603 + 0.00080340495 + 0.00026791636 + 0.0001069636 + 0.00072173367 + 0.0009843389 + 0.0005502449 + -0.00053331925 + -0.00082951237 + -0.000442981 + -0.00008059535 + 0.0000790719 + 0.00065935665 + 0.00057513634 + -0.0030332685 + 0.001132368 + -0.001431236 + -0.0006337841 + -0.0016255173 + -0.00030172226 + -0.00031614475 + -0.00045766454 + 0.0008159216 + -0.0005252184 + -0.00030048328 + -0.0027960406 + 0.0006808541 + -0.0029161815 + -0.00065310806 + 0.0006090027 + -0.00014221844 + -0.0009855228 + 0.00041428144 + -0.00017309522 + -0.000045343386 + 0.0013607923 + -0.0005750129 + 0.0005268442 + 0.000079675156 + 0.0008656121 + 0.0011809993 + -0.0003742615 + 0.00046851134 + 0.0001894508 + 0.0013740319 + 0.0000071505797 + 0.0008488567 + 0.00041412213 + 0.00028367396 + -0.002898284 + -0.0028179835 + 0.0007456284 + -0.0025346673 + -0.0023313926 + 0.00017695638 + -0.00012303199 + -0.000549279 + 0.0008334305 + 0.00051573815 + -0.0006247933 + -0.0037357209 + 0.00086800894 + -0.000765474 + 0.00030200687 + 0.0004425894 + 0.00018853998 + 0.00055940804 + 0.0016465153 + 0.00031594516 + 0.00021344195 + 0.00041679168 + 0.0009139059 + 0.00059773517 + -0.0020449993 + 0.00024514992 + -0.00041583274 + -0.0011266536 + 0.0005066153 + -0.00040034024 + -0.0008912287 + -0.00039037722 + 0.00093597913 + 0.00064652157 + -0.003183227 + 0.00041844905 + 0.0005388544 + -0.0026878177 + -0.0019869406 + -0.00041970643 + 0.00028848773 + -0.00011357613 + 0.000029491188 + 0.0006217879 + -0.000294195 + -0.00078267045 + -0.00036115389 + -0.00048519575 + -0.00280549 + 0.0001290137 + -0.00053962343 + -0.0001459577 + 0.0006226974 + -0.00006340456 + -0.00057018053 + -0.000153509 + -0.0002739703 + 0.00019646462 + 0.0009283192 + 0.0018709436 + -0.00059490086 + 0.0005238852 + 0.0005180927 + 0.00017826344 + -0.0000017986018 + 0.00077810703 + 0.00057792355 + 0.0010517646 + -0.0007303941 + 0.0010943573 + 0.00022734392 + 0.0010580912 + 0.00019590334 + -0.00016313369 + 0.0010868016 + 0.00013888239 + -0.00038767117 + 0.00061884837 + 0.0010490752 + -0.0025283124 + -0.0025096317 + -0.00266105 + -0.00259325 + -0.00038591036 + 0.00009707739 + 0.0009802519 + -0.00048499057 + 0.0012126286 + 0.00085677294 + 0.00019839949), 0.5 + (var126 + var127 + var128 + var129 + var130 + var131 + var132 + var133 + var134 + var135 + var136 + var137 + var138 + var139 + var140 + var141 + var142 + var143 + var144 + var145 + var146 + var147 + var148 + var149 + var150 + var151 + var152 + var153 + var154 + var155 + var156 + var157 + var158 + var159 + var160 + var161 + var162 + var163 + var164 + var165 + var166 + var167 + var168 + var169 + var170 + var171 + var172 + var173 + var174 + var175 + var176 + var177 + var178 + var179 + var180 + var181 + var182 + var183 + var184 + var185 + var186 + var187 + var188 + var189 + var190 + var191 + var192 + var193 + var194 + var195 + var196 + var197 + var198 + var199 + var200 + var201 + var202 + var203 + var204 + var205 + var206 + var207 + var208 + var209 + var210 + var211 + var212 + var213 + var214 + var215 + var216 + var217 + var218 + var219 + var220 + var221 + var222 + var223 + var224 + var225 + var226 + var227 + var228 + var229 + var230 + var231 + var232 + var233 + var234 + var235 + var236 + var237 + var238 + var239 + var240 + var241 + var242 + var243 + var244 + var245 + var246 + var247 + var248 + var249 + var250 + var251 + var252 + var253 + var254 + var255 + var256 + var257 + var258 + var259 + var260 + var261 + var262 + var263 + var264 + var265 + var266 + var267 + var268 + var269 + 0.0019140852 + var270 + var271 + var272 + var273 + -0.0021884192 + var274 + var275 + var276 + var277 + var278 + var279 + var280 + var281 + var282 + var283 + 0.0015220692 + var284 + 0.001239246 + var285 + var286 + -0.0010924973 + var287 + var288 + var289 + var290 + var291 + var292 + var293 + -0.0008842099 + -0.0005889323 + var294 + var295 + var296 + var297 + var298 + var299 + var300 + var301 + 0.0045916573 + var302 + var303 + var304 + var305 + var306 + var307 + 0.0008372469 + var308 + var309 + var310 + var311 + 0.002332336 + 0.00082495477 + 0.004593459 + 0.0005521251 + var312 + -0.000561789 + var313 + var314 + 0.0010432835 + 0.0007480984 + var315 + 0.0013242417 + 0.0018092316 + var316 + 0.0035354302 + var317 + var318 + -0.0018942606 + var319 + -0.0032437157 + 0.0022886747 + var320 + var321 + var322 + 0.000992997 + var323 + var324 + var325 + var326 + -0.0022791093 + var327 + var328 + var329 + 0.0020739443 + var330 + -0.0007319337 + -0.0032599345 + var331 + 0.0005109257 + 0.0007649063 + var332 + -0.0037967642 + var333 + 0.0010671468 + 0.0012573715 + var334 + var335 + -0.0020257155 + var336 + 0.002309328 + -0.002232705 + var337 + -0.0019327343 + var338 + -0.0019000898 + -0.0033914743 + -0.0009535816 + 0.001814558 + -0.0015344737 + -0.002630147 + var339 + -0.0013542204 + 0.0020979273 + var340 + 0.0013321093 + var341 + 0.0020596616 + 0.00009966862 + 0.005152258 + 0.0014551672 + var342 + var343 + 0.0042488 + -0.0009731102 + -0.0025384643 + -0.0009771121 + var344 + var345 + var346 + 0.0014819005 + var347 + -0.001643347 + var348 + 0.0013227825 + var349 + -0.0017500613 + -0.0019016502 + -0.00082943076 + -0.0035151497 + -0.00043184936 + var350 + var351 + var352 + -0.000132729 + 0.0051122904 + 0.0021250371 + -0.0013640573 + 0.000016691489 + -0.00081649324 + 0.0031972646 + var353 + 0.001839583 + var354 + 0.0008465728 + var355), 0.5 + (var356 + var357 + var358 + var359 + var360 + var361 + var362 + var363 + var364 + var365 + var366 + var367 + var368 + var369 + var370 + var371 + var372 + var373 + var374 + var375 + var376 + var377 + var378 + var379 + var380 + var381 + var382 + var383 + var384 + var385 + var386 + var387 + var388 + var389 + var390 + var391 + var392 + var393 + var394 + var395 + var396 + var397 + var398 + var399 + var400 + var401 + var402 + var403 + var404 + var405 + var406 + var407 + var408 + var409 + var410 + var411 + var412 + var413 + var414 + var415 + var416 + var417 + var418 + var419 + var420 + var421 + var422 + var423 + var424 + var425 + var426 + var427 + var428 + var429 + var430 + var431 + var432 + var433 + var434 + var435 + var436 + var437 + var438 + var439 + var440 + var441 + var442 + var443 + var444 + var445 + var446 + var447 + var448 + var449 + var450 + var451 + var452 + var453 + var454 + var455 + var456 + var457 + var458 + var459 + var460 + var461 + var462 + var463 + var464 + var465 + var466 + var467 + var468 + var469 + var470 + var471 + var472 + var473 + var474 + var475 + var476 + var477 + var478 + var479 + var480 + var481 + var482 + var483 + var484 + var485 + var486 + var487 + var488 + var489 + var490 + var491 + var492 + var493 + var494 + var495 + var496 + var497 + var498 + var499 + var500 + var501 + var502 + var503 + var504 + var505 + var506 + var507 + var508 + var509 + var510 + var511 + var512 + var513 + var514 + var515 + var516 + var517 + var518 + var519 + var520 + var521 + var522 + var523 + var524 + var525 + var526 + var527 + var528 + var529 + var530 + var531 + var532 + var533 + var534 + var535 + var536 + var537 + var538 + var539 + var540 + var541 + var542 + var543 + var544 + var545 + var546 + var547 + var548 + var549 + var550 + var551 + var552 + var553 + var554 + var555 + var556 + var557 + var558 + var559 + var560 + var561 + var562 + var563 + var564 + var565 + var566 + var567 + var568 + var569 + var570 + var571 + var572 + var573 + var574 + var575 + var576 + var577 + var578 + var579 + var580 + var581 + var582 + var583 + var584 + var585 + var586 + var587 + var588 + var589 + var590 + var591 + var592 + var593 + var594 + var595 + var596 + var597 + var598 + var599 + var600 + var601 + var602 + var603 + var604 + var605 + var606 + var607 + var608 + var609 + var610 + var611 + var612 + var613 + var614 + var615 + var616 + var617 + var618 + var619 + var620 + var621 + var622 + var623 + var624 + var625 + var626 + var627 + var628 + var629 + var630 + var631 + var632 + var633 + var634 + var635 + var636 + var637 + var638 + var639 + var640 + var641 + var642 + var643 + var644 + var645 + var646 + var647 + var648 + var649 + var650 + var651 + var652 + var653 + var654 + var655), 0.5 + (var656 + var657 + var658 + var659 + var660 + var661 + var662 + var663 + var664 + var665 + var666 + var667 + var668 + var669 + var670 + var671 + var672 + var673 + var674 + var675 + var676 + var677 + var678 + var679 + var680 + var681 + var682 + var683 + var684 + var685 + var686 + var687 + var688 + var689 + var690 + var691 + var692 + var693 + var694 + var695 + var696 + var697 + var698 + var699 + var700 + var701 + var702 + var703 + var704 + var705 + var706 + var707 + var708 + var709 + var710 + var711 + var712 + var713 + var714 + var715 + var716 + var717 + var718 + var719 + var720 + var721 + var722 + var723 + var724 + var725 + var726 + var727 + var728 + var729 + var730 + var731 + var732 + var733 + var734 + var735 + var736 + var737 + var738 + var739 + var740 + var741 + var742 + var743 + var744 + var745 + var746 + var747 + var748 + var749 + var750 + var751 + var752 + var753 + var754 + var755 + var756 + var757 + var758 + var759 + var760 + var761 + var762 + var763 + var764 + var765 + var766 + var767 + var768 + var769 + var770 + var771 + var772 + var773 + var774 + var775 + var776 + var777 + var778 + var779 + var780 + var781 + var782 + var783 + var784 + var785 + var786 + var787 + var788 + var789 + var790 + var791 + var792 + var793 + var794 + var795 + 0.002889102 + var796 + var797 + var798 + var799 + var800 + var801 + var802 + var803 + var804 + var805 + var806 + var807 + var808 + -0.007555702 + var809 + var810 + var811 + var812 + var813 + var814 + var815 + var816 + var817 + 0.0038572643 + var818 + var819 + var820 + -0.0054256706 + var821 + var822 + 0.0020556976 + -0.004833712 + -0.0048224833 + var823 + 0.00038236237 + 0.0047396836 + -0.0053075673 + var824 + var825 + 0.0033880204 + var826 + -0.002039823 + 0.0038559213 + var827 + var828 + var829 + -0.0037417945 + -0.0021793155 + var830 + 0.0042807697 + 0.003395835 + 0.003925863 + -0.0010806572 + var831 + -0.005074537 + var832 + 0.0034167853 + var833 + var834 + 0.0031787956 + -0.001618081 + 0.0015906565 + 0.001957904 + var835 + 0.0004342143 + var836 + -0.0051005655 + var837 + 0.0017590963 + 0.003742269 + var838 + var839 + -0.0017036187 + 0.0032483505 + -0.0042761206 + 0.005173931 + 0.0043858835 + 0.007782507 + var840 + -0.0016163056 + var841 + 0.002752847 + var842 + -0.004980002 + 0.007884993 + var843 + var844 + var845 + var846 + var847 + -0.00037749676 + 0.0007661591 + -0.0016539553 + 0.0032243778 + -0.0040778588 + -0.0043239743 + var848 + 0.0039713834 + 0.0045565986 + 0.0011107231 + var849 + 0.00085740996 + 0.0039664614 + var850 + 0.0009521192 + -0.0028188003 + var851 + -0.00066536944 + -0.0015871844 + 0.00041741828 + -0.0028963885 + -0.0033977851 + 0.004818343 + -0.007427712 + var852 + 0.0026603506 + -0.00072236446 + 0.00081437285 + var853 + var854 + 0.002942479 + var855 + -0.0043084514 + var856 + var857 + 0.007760778 + var858 + var859 + var860 + var861 + 0.0017826187 + 0.0027749483 + -0.000020699808 + var862 + -0.0032872779 + -0.0024054826 + -0.0015362888 + var863 + var864 + var865 + -0.0043316106 + -0.002532926 + var866 + var867 + -0.0019239475 + var868 + -0.0016202687 + -0.003363172 + 0.00029269836 + var869 + -0.006432362 + var870 + -0.0020949913 + 0.007797047 + -0.001913495 + 0.0006766273 + var871 + 0.0007081139 + -0.0002718051)};
    softmax(softmaxInput, 4, var0);
    memcpy(output, var0, 4 * sizeof(double));
}


// ============================================================
// COMPATIBILITY WRAPPER
// ============================================================
//
// The existing ESP32-S3 firmware expects:
//   output[0] = P(NORMAL)
//   output[1] = P(ATTACK)
//
// For the new four-class model, output[1] is a severity-weighted
// threat score instead of binary P(ATTACK).
//
static void score(
    const double *input,
    double *output
)
{
    double classProbability[4] = {0.0, 0.0, 0.0, 0.0};

    xgb4class_raw_score(
        (double *)input,
        classProbability
    );

    double weightedThreat =
        (
            classProbability[1] * (1.0 / 3.0)
        ) + (
            classProbability[2] * (2.0 / 3.0)
        ) + (
            classProbability[3]
        );

    output[0] = classProbability[0];
    output[1] = weightedThreat;
}

// ============================================================
// THREAT LEVEL
// ============================================================
static int getThreatLevel(
    float threat_probability
)
{
    if (threat_probability < THREAT_LOW)
        return THREAT_NORMAL;

    if (threat_probability < THREAT_HIGH)
        return THREAT_ELEVATED;

    return THREAT_CRITICAL;
}

#endif