import { runReviewCommand } from "./review.js";

export async function runVerifyCommand(args, options = {}) {
  await runReviewCommand(args, options);
}
