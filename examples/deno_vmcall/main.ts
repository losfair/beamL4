import { Vmcall } from "./vmcall.ts";

const N = 100;
const vmcall = new Vmcall();

while (true) {
    console.log(`Calling vmcall(1) ${N} times...`);
    const measurements = [];
    for (let i = 0; i < N; i++) {
        const startTime = performance.now();
        vmcall.vmcall.call(1n, 0n, 0n, 0n, 0n);
        const endTime = performance.now();
        measurements.push(endTime - startTime);
    }
    measurements.sort((a, b) => a - b);
    const median = measurements[Math.floor(N / 2)];
    const mean = measurements.reduce((a, b) => a + b, 0) / N;
    console.log(`median/mean: ${(median * 1000).toFixed(2)}us / ${(mean * 1000).toFixed(2)}us`);

    await new Promise((resolve) => setTimeout(resolve, 1000));
}
