import { twc } from "../lib/twc";
import React, { useState, useRef, useEffect } from 'react';
import Transition from '../lib/Transition';
function DropdownFilter({
  align
}) {
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const trigger = useRef(null);
  const dropdown = useRef(null);

  //Clear  filtres on click clear button

  const directorIndirectRef = useRef(null);
  const realTimeValueRef = useRef(null);
  const topChannelsRef = useRef(null);
  const salesRefundsRef = useRef(null);
  const lastOrderRef = useRef(null);
  const totalSpentRef = useRef(null);
  const handleFilters = () => {
    [directorIndirectRef, realTimeValueRef, topChannelsRef, salesRefundsRef, lastOrderRef, totalSpentRef].forEach(checkboxRef => {
      if (checkboxRef.current?.checked) {
        checkboxRef.current.checked = false;
      }
    });
  };

  // close on click outside
  useEffect(() => {
    const clickHandler = ({
      target
    }) => {
      if (!dropdown.current) return;
      if (!dropdownOpen || dropdown.current.contains(target) || trigger.current.contains(target)) return;
      setDropdownOpen(false);
    };
    document.addEventListener('click', clickHandler);
    return () => document.removeEventListener('click', clickHandler);
  });

  // close if the esc key is pressed
  useEffect(() => {
    const keyHandler = ({
      keyCode
    }) => {
      if (!dropdownOpen || keyCode !== 27) return;
      setDropdownOpen(false);
    };
    document.addEventListener('keydown', keyHandler);
    return () => document.removeEventListener('keydown', keyHandler);
  });
  return <div className={twc("relative inline-flex")}>
      <button ref={trigger} className={twc("btn px-2.5 bg-white dark:bg-gray-800 border-gray-200 hover:border-gray-300 dark:border-gray-700/60 dark:hover:border-gray-600 text-gray-400 dark:text-gray-500")} aria-haspopup="true" onClick={() => setDropdownOpen(!dropdownOpen)} aria-expanded={dropdownOpen}>
        <span className={twc("sr-only")}>Filter</span>
        <wbr />
        <svg className={twc("fill-current")} width="16" height="16" viewBox="0 0 16 16">
          <path d="M0 3a1 1 0 0 1 1-1h14a1 1 0 1 1 0 2H1a1 1 0 0 1-1-1ZM3 8a1 1 0 0 1 1-1h8a1 1 0 1 1 0 2H4a1 1 0 0 1-1-1ZM7 12a1 1 0 1 0 0 2h2a1 1 0 1 0 0-2H7Z" />
        </svg>
      </button>
      <Transition show={dropdownOpen} tag="div" className={twc(`origin-top-right z-10 absolute top-full left-0 right-auto min-w-56 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700/60 pt-1.5 rounded-lg shadow-lg overflow-hidden mt-1 ${align === 'right' ? 'md:left-auto md:right-0' : 'md:left-0 md:right-auto'}`)} enter="transition ease-out duration-200 transform" enterStart="opacity-0 -translate-y-2" enterEnd="opacity-100 translate-y-0" leave="transition ease-out duration-200" leaveStart="opacity-100" leaveEnd="opacity-0">
        <div ref={dropdown}>
          <div className={twc("text-xs font-semibold text-gray-400 dark:text-gray-500 uppercase pt-1.5 pb-2 px-3")}>
            Filters
          </div>
          <ul className={twc("mb-4")}>
            <li className={twc("py-1 px-3")}>
              <label className={twc("flex items-center")}>
                <input ref={directorIndirectRef} type="checkbox" className={twc("form-checkbox")} />
                <span className={twc("text-sm font-medium ml-2")}>
                  Direct VS Indirect
                </span>
              </label>
            </li>
            <li className={twc("py-1 px-3")}>
              <label className={twc("flex items-center")}>
                <input ref={realTimeValueRef} type="checkbox" className={twc("form-checkbox")} />
                <span className={twc("text-sm font-medium ml-2")}>
                  Real Time Value
                </span>
              </label>
            </li>
            <li className={twc("py-1 px-3")}>
              <label className={twc("flex items-center")}>
                <input ref={topChannelsRef} type="checkbox" className={twc("form-checkbox")} />
                <span className={twc("text-sm font-medium ml-2")}>Top Channels</span>
              </label>
            </li>
            <li className={twc("py-1 px-3")}>
              <label className={twc("flex items-center")}>
                <input ref={salesRefundsRef} type="checkbox" className={twc("form-checkbox")} />
                <span className={twc("text-sm font-medium ml-2")}>
                  Sales VS Refunds
                </span>
              </label>
            </li>
            <li className={twc("py-1 px-3")}>
              <label className={twc("flex items-center")}>
                <input ref={lastOrderRef} type="checkbox" className={twc("form-checkbox")} />
                <span className={twc("text-sm font-medium ml-2")}>Last Order</span>
              </label>
            </li>
            <li className={twc("py-1 px-3")}>
              <label className={twc("flex items-center")}>
                <input ref={totalSpentRef} type="checkbox" className={twc("form-checkbox")} />
                <span className={twc("text-sm font-medium ml-2")}>Total Spent</span>
              </label>
            </li>
          </ul>
          <div className={twc("py-2 px-3 border-t border-gray-200 dark:border-gray-700/60 bg-gray-50 dark:bg-gray-700/20")}>
            <ul className={twc("flex items-center justify-between")}>
              <li>
                <button onClick={handleFilters} className={twc("btn-xs bg-white dark:bg-gray-800 border-gray-200 dark:border-gray-700/60 hover:border-gray-300 dark:hover:border-gray-600 text-red-500")}>
                  Clear
                </button>
              </li>
              <li>
                <button className={twc("btn-xs bg-gray-900 text-gray-100 hover:bg-gray-800 dark:bg-gray-100 dark:text-gray-800 dark:hover:bg-white")} onClick={() => setDropdownOpen(false)} onBlur={() => setDropdownOpen(false)}>
                  Apply
                </button>
              </li>
            </ul>
          </div>
        </div>
      </Transition>
    </div>;
}
export default DropdownFilter;
