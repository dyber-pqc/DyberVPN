import styles from "./ModeTag.module.css";

export function ModeTag({ mode }) {
  const variant = styles[mode] || styles.classic;
  return <span className={`${styles.tag} ${variant}`}>{mode}</span>;
}
