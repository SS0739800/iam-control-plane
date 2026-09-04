/**
 * A tab strip for detail pages with a few sections worth separating (Overview,
 * Members, and so on). Every tab's content stays in the DOM the whole time — we
 * only hide the ones that aren't picked — so nothing here can make a piece of
 * page content disappear from something that looks for it by text.
 */

import { useId, useState } from 'react'

import { cx } from '../lib/cx'
import styles from './Tabs.module.css'

export type TabDef = { id: string; label: string; content: React.ReactNode }

export function Tabs({ tabs, defaultTabId }: { tabs: TabDef[]; defaultTabId?: string }) {
  const [activeId, setActiveId] = useState(defaultTabId ?? tabs[0]?.id)
  const baseId = useId()

  return (
    <div>
      <div role="tablist" className={styles.tabList}>
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            role="tab"
            id={`${baseId}-tab-${tab.id}`}
            aria-selected={tab.id === activeId}
            aria-controls={`${baseId}-panel-${tab.id}`}
            className={cx(styles.tab, tab.id === activeId && styles.tabActive)}
            onClick={() => setActiveId(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>
      {tabs.map((tab) => (
        <div
          key={tab.id}
          role="tabpanel"
          id={`${baseId}-panel-${tab.id}`}
          aria-labelledby={`${baseId}-tab-${tab.id}`}
          hidden={tab.id !== activeId}
        >
          {tab.content}
        </div>
      ))}
    </div>
  )
}
