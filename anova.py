import pandas as pd
import scipy.stats as stats
from statsmodels.stats.multicomp import pairwise_tukeyhsd

# Example data
data = {
    "Algorithm": ["Argon2"]*5 + ["bcrypt"]*5 + ["scrypt"]*5 + ["PBKDF2"]*5,
    "Execution_Time": [0.8714, 0.5507, 1.3637, 0.6634, 1.7621,  # Argon2
               1.0757, 0.6134, 1.7741, 0.8415, 2.3707,  # bcrypt
               9.7844, 4.9895, 14.386, 7.3662, 18.463,  # scrypt
               6.7367, 3.7835, 11.1013, 5.3745, 14.1477]  # PBKDF2
}

df = pd.DataFrame(data)

# Perform one-way ANOVA
f_stat, p_value = stats.f_oneway(
    df[df["Algorithm"] == "Argon2"]["Execution_Time"],
    df[df["Algorithm"] == "bcrypt"]["Execution_Time"],
    df[df["Algorithm"] == "scrypt"]["Execution_Time"],
    df[df["Algorithm"] == "PBKDF2"]["Execution_Time"]
)

print("F-statistic:", f_stat)
print("P-value:", p_value)

# Post-hoc analysis if ANOVA is significant
if p_value < 0.05:
    tukey = pairwise_tukeyhsd(endog=df["Execution_Time"], groups=df["Algorithm"], alpha=0.05)
    print(tukey)

